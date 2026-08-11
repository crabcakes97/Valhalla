#!/usr/bin/env python3
"""
Tool to rebuild or concatenate MTK part_hdr_t multi-image files.

Features:
- replace: replace a single sub-image (by name) in an existing multi-image file
  with a provided single-image file (header+data) or raw data file.
  Writes output to specified path or <input>.new by default.

- concat: concatenate single-image files from a directory in a specified order
  (or default order: lk bl2_ext aee lk_main_dtb lk_dtbo) to create a new
  multi-image file.

This script expects single-image files to contain a 512-byte part_hdr_t followed
by the image data (split produced files). Concatenation joins single-image
files directly (no additional padding). Replacement uses the entire single-image
file (header+data and any embedded cert headers) to replace the corresponding
region in a multi-image file.
"""
from __future__ import print_function

import argparse
import os
import re
import struct
import sys

PART_MAGIC = 0x58881688
PART_HEADER_DEFAULT_ADDR = 0xFFFFFFFF
PART_HDR_SIZE = 512
CHUNK_SIZE = 1024 * 1024
PART_HDR_FORMAT = "<II32sIIIIIIIIII"


class ParseError(Exception):
    pass


def roundup(value, align):
    if align <= 0:
        raise ParseError("invalid align_sz: %d" % align)
    return (value + align - 1) & ~(align - 1)


def decode_name(raw_name):
    name = raw_name.split(b"\0", 1)[0]
    try:
        return name.decode("ascii")
    except UnicodeDecodeError:
        return name.decode("latin-1")


def sanitize_filename(name):
    name = name.strip()
    if not name:
        name = "unnamed"
    name = re.sub(r'[<>:\\"/\\|?*\x00-\x1f]', "_", name)
    name = name.rstrip(" .")
    return name or "unnamed"


class PartHdr(object):
    def __init__(self, values, raw=None):
        self.magic = values[0]
        self.dsize = values[1]
        self.name = decode_name(values[2])
        self.maddr = values[3]
        self.mode = values[4]
        self.ext_magic = values[5]
        self.hdr_sz = values[6]
        self.hdr_ver = values[7]
        self.img_type = values[8]
        self.img_list_end = values[9]
        self.align_sz = values[10]
        self.dsize_extend = values[11]
        self.maddr_extend = values[12]
        self._raw = raw

    @classmethod
    def parse(cls, data):
        if len(data) < PART_HDR_SIZE:
            raise ParseError("short part_hdr_t: got %d bytes" % len(data))
        values = struct.unpack_from(PART_HDR_FORMAT, data, 0)
        return cls(values, raw=data[:PART_HDR_SIZE])

    def data_size(self):
        return self.dsize

    def align_size(self):
        return self.align_sz

    def padded_data_size(self):
        return roundup(self.data_size(), self.align_size())

    def next_offset(self, offset):
        return offset + PART_HDR_SIZE + self.padded_data_size()


def read_hdr_with_raw(fp, offset, file_size):
    if file_size - offset < PART_HDR_SIZE:
        raise ParseError(
            "offset 0x%x has only %d bytes left, smaller than part_hdr_t"
            % (offset, file_size - offset)
        )
    fp.seek(offset)
    data = fp.read(PART_HDR_SIZE)
    if len(data) != PART_HDR_SIZE:
        raise ParseError("failed to read part_hdr_t at offset 0x%x" % offset)
    hdr = PartHdr.parse(data)
    return hdr, data


def iter_images_with_raw(fp, file_size):
    offset = 0
    index = 0
    while offset < file_size:
        hdr, raw = read_hdr_with_raw(fp, offset, file_size)
        if hdr.magic != PART_MAGIC:
            raise ParseError(
                "header magic error at offset 0x%x: 0x%08x != 0x%08x"
                % (offset, hdr.magic, PART_MAGIC)
            )
        data_offset = offset + PART_HDR_SIZE
        padded = hdr.padded_data_size()
        next_offset = offset + PART_HDR_SIZE + padded
        if data_offset + hdr.data_size() > file_size:
            raise ParseError("%s data exceeds file size" % hdr.name)
        yield index, offset, data_offset, hdr, raw, padded
        index += 1
        offset = next_offset
        if hdr.img_list_end:
            break


def copy_stream(src_fp, dst_fp, offset, size):
    src_fp.seek(offset)
    remaining = size
    while remaining:
        chunk = src_fp.read(min(CHUNK_SIZE, remaining))
        if not chunk:
            raise ParseError("unexpected EOF while copying stream")
        dst_fp.write(chunk)
        remaining -= len(chunk)


def replace_mode(input_path, target_name, new_file, out_path=None, verbose=False):
    """Replace the target sub-image region (header + image + cert1/cert2 if present)
    with the entire contents of `new_file` (copied as-is).
    """
    if out_path is None:
        out_path = input_path + ".new"
    file_size = os.path.getsize(input_path)
    replaced = False
    with open(input_path, "rb") as src_fp, open(out_path, "wb") as out_fp:
        offset = 0
        index = 0
        while offset < file_size:
            hdr, raw_hdr = read_hdr_with_raw(src_fp, offset, file_size)
            name = hdr.name
            data_offset = offset + PART_HDR_SIZE
            padded = hdr.padded_data_size()
            if verbose:
                print("processing image %d: %s" % (index, name))

            if name == target_name:
                replaced = True
                # determine original region including potential following cert headers
                orig_end = offset + PART_HDR_SIZE + padded
                cur_check_off = orig_end

                def is_cert(hdr_obj):
                    if not hdr_obj:
                        return False
                    return (hdr_obj.name or "").lower().startswith('cert')

                # peek cert1
                try:
                    next_hdr, _ = read_hdr_with_raw(src_fp, cur_check_off, file_size)
                except ParseError:
                    next_hdr = None

                if is_cert(next_hdr):
                    cert1_end = next_hdr.next_offset(cur_check_off)
                    orig_end = cert1_end
                    cur_check_off = cert1_end
                    try:
                        next2_hdr, _ = read_hdr_with_raw(src_fp, cur_check_off, file_size)
                    except ParseError:
                        next2_hdr = None
                    if is_cert(next2_hdr):
                        cert2_end = next2_hdr.next_offset(cur_check_off)
                        orig_end = cert2_end

                # copy replacement file bytes into output (replace entire region)
                if verbose:
                    print("replacing region 0x%x..0x%x with %s" % (offset, orig_end, new_file))
                with open(new_file, 'rb') as nf:
                    copy_stream(nf, out_fp, 0, os.path.getsize(new_file))

                # skip past the original full region (main + certs)
                offset = orig_end
                index += 1
                # continue reading from new offset (do not copy the original certs)
                continue
            else:
                # copy original header + padded data as-is (preserve original padding)
                out_fp.write(raw_hdr)
                copy_stream(src_fp, out_fp, data_offset, padded)
                offset = offset + PART_HDR_SIZE + padded
                index += 1
                if hdr.img_list_end:
                    break
    if not replaced:
        raise ParseError("image not found: %s" % target_name)
    print("wrote rebuilt image to %s" % out_path)


def concat_mode(dir_path, order_names=None, out_path=None, verbose=False):
    if order_names is None or len(order_names) == 0:
        order_names = ["lk", "bl2_ext", "aee", "lk_main_dtb", "lk_dtbo"]
    if out_path is None:
        out_path = os.path.basename(os.path.normpath(dir_path)) + ".new"

    files_to_concat = []
    for name in order_names:
        fname = sanitize_filename(name) + ".bin"
        fpath = os.path.join(dir_path, fname)
        if os.path.exists(fpath):
            files_to_concat.append((name, fpath))
            if verbose:
                print("will include: %s" % fpath)

    # also include any additional files in directory not in order? No — follow requested order only.
    if not files_to_concat:
        raise ParseError("no files found to concat in %s" % dir_path)

    with open(out_path, "wb") as out_fp:
        for name, fpath in files_to_concat:
            if verbose:
                print("adding %s" % fpath)
            with open(fpath, "rb") as f:
                # copy file contents as-is
                f.seek(0)
                remaining = os.path.getsize(fpath)
                while remaining:
                    chunk = f.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ParseError("unexpected EOF while reading %s" % fpath)
                    out_fp.write(chunk)
                    remaining -= len(chunk)
    print("wrote concatenated image to %s" % out_path)


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Build/modify MTK part_hdr_t multi-image files")
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_replace = sub.add_parser('replace', help='replace a single sub-image in an existing multi-image')
    p_replace.add_argument('image', help='input multi-image file')
    p_replace.add_argument('--name', required=True, help='sub-image name to replace')
    p_replace.add_argument('--file', required=True, help='replacement single-image file (header+data, may include certs)')
    p_replace.add_argument('-o', '--out', help='output file path, default: <image>.new')
    # No separate cert files needed; replacement single-image file should
    # include any cert headers if present (the script will replace the
    # original region including cert1/cert2 if they exist).
    p_replace.add_argument('-v', '--verbose', action='store_true')

    p_concat = sub.add_parser('concat', help='concatenate single-image files from a directory')
    p_concat.add_argument('dir', help='directory containing single-image files (name.bin)')
    p_concat.add_argument('--order', help='comma-separated image names in desired order')
    p_concat.add_argument('-o', '--out', help='output file path, default: <dir>.new')
    p_concat.add_argument('-v', '--verbose', action='store_true')

    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv[1:])
    try:
        if args.cmd == 'replace':
            replace_mode(args.image, args.name, args.file, out_path=args.out, verbose=args.verbose)
        elif args.cmd == 'concat':
            order = None
            if args.order:
                order = [s.strip() for s in args.order.split(',') if s.strip()]
            concat_mode(args.dir, order_names=order, out_path=args.out, verbose=args.verbose)
    except (IOError, OSError, ParseError) as err:
        print("error: %s" % err, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
