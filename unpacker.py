import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
import struct
import time
from concurrent.futures import ThreadPoolExecutor

fp = open('./list.txt', 'w')
SIGN_FMT = ">3ss4sII"
SINGNATURES = [0x10C, 0x3EA]
tag_type_map = {3: "INT_16", 4: "INT_32", 5: "INT_64"}


def rpm_divide(path, dest):
    if not os.path.exists(dest):
        os.mkdir(dest)
    with open(path, "rb") as f:
        lead_buffer = f.read(0x60)
        magic, version, reserved, index_num, sign_size = unpack_rpm(SIGN_FMT, f, 0x60)
        indexes = list()
        f.seek(0x70)
        tag_buffer_offset = 0x70 + index_num * 0x10
        for i in range(index_num):
            tag, tag_type, tag_offset, tag_size = unpack_rpm(IndexEntry.FMT, f, f.tell())
            indexes.append(IndexEntry(f, tag, tag_type, tag_offset, tag_size, tag_buffer_offset, i))

        has_signature = list(filter(lambda x: x.tag in SINGNATURES, indexes))
        if has_signature == None:
            return None
        rsa_tag, pgp_tag = has_signature
        tag_info_buffer, tag_buffer = bytes(), bytes()
        indexes = sorted(indexes, key=lambda x: x.tag_offset)
        for n, index in enumerate(indexes):
            buffer = index.data
            if index.tag in SINGNATURES:
                continue
            elif index.tag_type == 6:
                buffer_len = indexes[n + 1].tag_offset - index.tag_offset
                f.seek(tag_buffer_offset + index.tag_offset)
                buffer = f.read(buffer_len)
            elif tag_type_map.get(index.tag_type):
                padding, bytes_cnt = patch_bytes(tag_type_map[index.tag_type], len(tag_buffer))
                f.seek(tag_buffer_offset + index.tag_offset)
                buffer = f.read(bytes_cnt)
                tag_buffer += padding * b"\x00"
            elif not index.index and index.tag == 0x3E:
                temp_bytes = (1 << 32) - (index_num - 1 - len(has_signature)) * 0x10 - index.tag_size
                temp_bytes = temp_bytes.to_bytes(4, byteorder="big")
                buffer = buffer[:8] + temp_bytes + buffer[12:]
            index.tag_offset = len(tag_buffer)
            tag_buffer += buffer
            buffer = struct.pack(IndexEntry.FMT, index.tag, index.tag_type, index.tag_offset, index.tag_size)
            if index.index:
                tag_info_buffer += buffer
            else:
                tag_info_buffer = buffer + tag_info_buffer
        padding, _ = patch_bytes(8, len(tag_buffer))
        head_buffer = struct.pack(
            SIGN_FMT, magic, version, reserved, index_num - len(has_signature), len(tag_buffer)
        )
        header = lead_buffer + head_buffer + tag_info_buffer + tag_buffer

        with open(
                os.path.join(os.path.join(dest, "RSA")), "wb"
        ) as rsa_descriptor:
            rsa_descriptor.write(rsa_tag.data)

        with open(
                os.path.join(os.path.join(dest, "PGP")), "wb"
        ) as pgp_descriptor:
            pgp_descriptor.write(pgp_tag.data)

        with open(
                os.path.join(dest, os.path.basename(path)), "wb"
        ) as rpm_file_descriptor:
            rpm_file_descriptor.write(header)
            f.seek(tag_buffer_offset + sign_size)
            last_buffer = f.read().lstrip(b"\x00")
            rpm_file_descriptor.write(b"\x00" * padding + last_buffer)
    return dest


def patch_bytes(tag_type, offset):
    """Find the padding numbers needed.

        Args:
            tag_type: the rpm tag type
            offset: the offset of file descriptor

        Returns:
            tuple
        """
    res = 0
    if not isinstance(tag_type, int):
        tag_type = int(tag_type.split("_")[-1]) / 8
    _, mod = divmod(offset, tag_type)
    if mod:
        res = int(tag_type - mod)
    return res, int(tag_type)


def unpack_rpm(fmt, file_descriptor, offset, reverse=False):
    """Unpack file with the format.

        Args:
            fmt(str):format
            file_descriptor:file object
            offset(int):

        Returns:
            content after unpack

        Raises:
            BufferError:buffer length error
        """
    if offset < 0:
        raise ValueError("offset error %d < 0" % offset)
    seek_type, offset = (os.SEEK_END, -offset) if reverse else (os.SEEK_SET, offset)
    file_descriptor.seek(offset, seek_type)
    size = struct.calcsize(fmt)
    try:
        return struct.unpack(fmt, file_descriptor.read(size))
    except struct.error:
        buff_error = BufferError("Needed buffer of length {0}".format(struct.calcsize(fmt)))
        raise buff_error.__class__(buff_error).with_traceback(sys.exc_info()[2])


class IndexEntry:
    FMT = ">IIII"

    def __init__(self, fd, tag, tag_type, tag_offset, tag_size, tag_buffer_offset=0, index=0):
        """Create a new indexEntry instance.

            Args:
                fd (file): the file descriptor
                tag (int): rpm tag
                tag_type (int): rpm tag type
                tag_offset (int): the tag offset in the rpm file
                tag_size (int): the tag occupied siez
                tag_buffer_offset (int): the tag content offset
                index (int): the location of tag
            """
        self.file_descriptor = fd
        self.tag = tag
        self.tag_type = tag_type
        self.tag_offset = tag_offset
        self.tag_size = tag_size
        self.tag_buffer_offset = tag_buffer_offset
        self.index = index

    @property
    def data(self):
        """The property of the IndexEntry class.
            """
        self.file_descriptor.seek(self.tag_offset + self.tag_buffer_offset)
        return self.file_descriptor.read(self.tag_size)


class CommonFunCmd:
    @staticmethod
    def subprocess_func(cmd, *args, exit=True, cwd=None):
        logging.info("start to execute the command: " + cmd)
        try:
            p = subprocess.Popen(cmd, shell=True, cwd=cwd)
            p.wait()
            return_code = p.returncode
            if return_code != 0:
                print(return_code)
                raise Exception(return_code)
        except Exception as e:
            if exit:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))
                raise Exception(cmd)
            else:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))

    @staticmethod
    def subprocess_diffoscope(cmd, *args, exit=True, cwd=None):
        logging.info("start to execute the command: " + cmd)
        try:
            p = subprocess.Popen(cmd, shell=True, cwd=cwd)
            p.wait()
            return p.returncode
        except Exception as e:
            if exit:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))
                raise Exception(cmd)
            else:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))

    @staticmethod
    def subprocess_result(cmd, *args, exit=True, cwd=None):
        logging.info("start to execute the command: " + cmd)
        sys.getfilesystemencoding()
        out_temp = tempfile.TemporaryFile(mode='w+')
        try:
            file_no = out_temp.fileno()
            chd = subprocess.Popen(cmd, shell=True, stdout=file_no, cwd=cwd)
            chd.wait()
            out_temp.seek(0)
            res = out_temp.read().strip().split('\n')[0]
            return res
        except Exception as e:
            if exit:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))
                raise Exception(cmd)
            else:
                logging.error("Command:%s\n    Reason:%s\n%s" % (cmd, e.__str__(), "".join(tuple(args))))
        finally:
            if out_temp:
                out_temp.close()


class Unpack:
    def __init__(self, args=None):
        self.args = args
        self.same = True
        self.file1 = os.path.abspath(args[0])
        self.file2 = os.path.abspath(args[1])

    @staticmethod
    def if_compress_format(file):
        compress_format = ['.gz', '.rpm', '.zip', '.7z', '.rar', '.jar', '.whl', '.war', '.apk', '.ipa', '.dep']
        file_format = os.path.splitext(file)[1]
        if file_format in compress_format:
            return True
        else:
            return False

    def get_md5(self, file):
        md5 = hashlib.md5()
        with open(file, "rb") as f:
            while True:
                date = f.read(4096)
                if not date:
                    break
                md5.update(date)
        # cmd = "md5sum {}".format(file)
        # md5 = CommonFunCmd.subprocess_result(cmd)
        return md5.hexdigest()

    def compare_md5(self, file1, file2):
        dest1 = file1 + '_tmp11'
        dest2 = file2 + '_tmp22'
        if file1.endswith(".rpm"):
            result1 = rpm_divide(file1, dest1)
            result2 = rpm_divide(file2, dest2)
            if result1 is not None or result2 is not None:
                file1 = file1 + '_tmp11/' + os.path.basename(file1)
                file2 = file2 + '_tmp22/' + os.path.basename(file2)
        if self.get_md5(file1) == self.get_md5(file2):
            if os.path.exists(dest1) and os.path.exists(dest2):
                shutil.rmtree(dest1)
                shutil.rmtree(dest2)
            return True
        else:
            if os.path.exists(dest1) and os.path.exists(dest2):
                shutil.rmtree(dest1)
                shutil.rmtree(dest2)
            return False

    @staticmethod
    def deal_tgz(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("tar -xf {} ".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_rpm(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_diffoscope("rpm2cpio {} | cpio -idm".format(os.path.basename(file)),
                                           cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_zip(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        fz = zipfile.ZipFile(os.path.join(path_name, dir_name, os.path.basename(file)), 'r')

        for f in fz.namelist():
            fz.extract(f, path=os.path.join(path_name, dir_name))
        fz.close()
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    @staticmethod
    def deal_7z(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("7za e {}".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_rar(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("rar x {}".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_jar_war(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("jar xf {}".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_whl(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("wheel unpack {}".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_apk(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("mv {} {}".format(os.path.basename(file),
                                                       os.path.basename(file).replace(".apk", ".zip")),
                                     cwd=os.path.join(path_name, dir_name))
        CommonFunCmd.subprocess_func("unzip -q {}".format(os.path.basename(file).replace(".apk", ".zip")),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file).replace(".apk", ".zip")))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_ipa(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("mv {} {}".format(os.path.basename(file),
                                                       os.path.basename(file).replace(".ipa", ".zip")),
                                     cwd=os.path.join(path_name, dir_name))
        CommonFunCmd.subprocess_func("unzip -q {}".format(os.path.basename(file).replace(".ipa", ".zip")),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file).replace(".ipa", ".zip")))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_dep(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("dbkg -x {} ./".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    @staticmethod
    def deal_gz(file, dir_name):
        path_name = os.path.dirname(os.path.abspath(file))
        if dir_name != "":
            Unpack.pre_act(dir_name, file, path_name)
        CommonFunCmd.subprocess_func("gzip -d {} ".format(os.path.basename(file)),
                                     cwd=os.path.join(path_name, dir_name))
        os.remove(os.path.join(path_name, dir_name, os.path.basename(file)))
        return os.path.join(path_name, dir_name)

    def unpack(self, file, dir_name=""):
        if os.path.exists(file) and not os.path.getsize(file):
            print("file {} is empty file".format(file))
            sys.exit(0)
        if file.endswith(".tar.gz"):
            return self.deal_tgz(file, dir_name)
        elif file.endswith(".rpm"):
            return self.deal_rpm(file, dir_name)
        elif file.endswith(".zip"):
            return self.deal_zip(file, dir_name)
        elif file.endswith(".7z"):
            return self.deal_7z(file, dir_name)
        elif file.endswith(".rar"):
            return self.deal_rar(file, dir_name)
        elif file.endswith(".jar") or file.endswith(".war"):
            return self.deal_jar_war(file, dir_name)
        elif file.endswith(".whl"):
            return self.deal_whl(file, dir_name)
        elif file.endswith(".apk"):
            return self.deal_apk(file, dir_name)
        elif file.endswith(".ipa"):
            return self.deal_ipa(file, dir_name)
        elif file.endswith(".dep"):
            return self.deal_dep(file, dir_name)
        elif file.endswith(".gz"):
            return self.deal_gz(file, dir_name)

    def get_all_file(self, bate_path, path, elem=None):
        if elem is None:
            elem = []
            zip_elem = []
        for root, ds, fs in os.walk(path):
            for f in fs:
                full_path = os.path.join(root, f)
                if self.if_compress_format(full_path):
                    rela_path = full_path[len(bate_path):]
                    zip_elem.append(rela_path)
                else:
                    rela_path = full_path[len(bate_path):]
                    elem.append(rela_path)
        return elem, zip_elem

    def compare_dir(self, path1, path2, name1, name2):
        files1, zip_files1 = self.get_all_file(path1, path1)
        files2, zip_files2 = self.get_all_file(path2, path2)
        set1 = set(files1)
        set2 = set(files2)

        common_files = set1 & set2

        for file in common_files:
            if os.path.islink(path1 + file) or os.path.islink(path2 + file):
                continue
            if not self.compare_md5(path1 + file, path2 + file):
                fp.write(file + '    N')
                if self.if_compress_format(file):
                    fp.write(' Y\n')
                else:
                    fp.write('\n')
                dir_name = name1 + '_' + name2
                if name1 == name2:
                    dir_name = name1
                if not os.path.exists('./diffoscope/{}'.format(dir_name)):
                    os.makedirs('./diffoscope/{}'.format(dir_name), 0o755)
                return_code = CommonFunCmd.subprocess_diffoscope(
                    "diffoscope --html ./diffoscope/{}/diffoscope_{}.html {} {}"
                        .format(dir_name, os.path.basename(file), path1 + file, path2 + file))
                if return_code == 1:
                    self.same = False
                    print("file {} is not same".format(name1 + file))
                else:
                    self.same = True
                    print("file {} is same".format(name1 + file))
                continue
            fp.write(file + '    Y\n')

        only_files = set1 ^ set2
        only_set1 = []
        only_set2 = []
        for file in only_files:
            if file in files1:
                only_set1.append(file)
            elif file in files2:
                only_set2.append(file)

        if len(only_set1) != 0:
            self.same = False
            print("file {} is only in file1".format(only_set1))
        if len(only_set2) != 0:
            self.same = False
            print("file {} is only in file2".format(only_set2))

        zip_set1 = set(zip_files1)
        zip_set2 = set(zip_files2)

        common_zip_files = zip_set1 & zip_set2

        for file in common_zip_files:
            if file is None or os.path.islink(file):
                continue
            if not self.compare_md5(path1 + '/' + file, path2 + '/' + file):
                fp.write(file + '    N N\n')
                path_dir1 = self.unpack(path1 + '/' + file, file + '_tmp111')
                path_dir2 = self.unpack(path2 + '/' + file, file + '_tmp222')
                rpm1_name = os.path.basename(file)
                rpm2_name = os.path.basename(file)
                self.compare_dir(path_dir1, path_dir2, rpm1_name, rpm2_name)
                continue
            fp.write(file + '    Y Y\n')

        only_zip_files = zip_set1 ^ zip_set2
        only_zip_set1 = []
        only_zip_set2 = []
        for file in only_zip_files:
            if file in zip_files1:
                only_zip_set1.append(file)
            elif file in zip_files2:
                only_zip_set2.append(file)

        if len(only_zip_set1) != 0:
            self.same = False
            print("zip file {} is only in file1".format(only_zip_set1))
        if len(only_zip_set2) != 0:
            self.same = False
            print("zip file {} is only in file2".format(only_zip_set2))
        return

    @staticmethod
    def pre_act(dir_name, file, path_name):
        if not os.path.exists(os.path.join(path_name, dir_name)):
            os.makedirs(os.path.join(path_name, dir_name))
        shutil.copy(file, os.path.join(path_name, dir_name))


def create_parser(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--exclude", help="exclude file")


def task(unpack, args, file):
    path_dir1 = unpack.unpack(args[0] + file, file + "_tmp1")
    path_dir2 = unpack.unpack(args[1] + file, file + "_tmp2")
    unpack.compare_dir(path_dir1, path_dir2, file, file)
    shutil.rmtree(path_dir1)
    shutil.rmtree(path_dir2)


def main(args):
    if os.path.isfile(args[0]) and os.path.isfile(args[1]):
        unpack = Unpack(args)
        create_parser(args)
        is_same = unpack.compare_md5(args[0], args[1])
        rpm1_name = os.path.basename(args[0])
        rpm2_name = os.path.basename(args[1])
        if not is_same:
            path_dir1 = unpack.unpack(args[0], rpm1_name + "_tmp1")
            path_dir2 = unpack.unpack(args[1], rpm2_name + "_tmp2")
            unpack.compare_dir(path_dir1, path_dir2, rpm1_name, rpm2_name)
            shutil.rmtree(path_dir1)
            shutil.rmtree(path_dir2)
        if unpack.same:
            print("files {} and {} are same!".format(rpm1_name, rpm2_name))
        else:
            print("files {} and {} are not same!".format(rpm1_name, rpm2_name))
    elif os.path.isdir(args[0]) and os.path.isdir(args[1]):
        files1 = []
        files2 = []
        for root, ds, fs in os.walk(args[0]):
            for f in fs:
                f_name = os.path.join(root, f).replace(args[0], '')
                files1.append(f_name)
        for root, ds, fs in os.walk(args[1]):
            for f in fs:
                f_name = os.path.join(root, f).replace(args[1], '')
                files2.append(f_name)
        set1 = set(files1)
        set2 = set(files2)
        common_file = set1 & set2
        pool = ThreadPoolExecutor(max_workers=3)
        for file in common_file:
            unpack = Unpack(args)
            create_parser(args)
            is_same = unpack.compare_md5(args[0] + file, args[1] + file)
            if not is_same:
                pool.submit(task, unpack, args, file)
                time.sleep(5)
            if unpack.same:
                print("files {} and {} are same!".format(file, file))
            else:
                print("files {} and {} are not same!".format(file, file))
    else:
        logging.error("the arg is not a file!")


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    main(sys.argv[1:])
