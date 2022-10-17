import argparse
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import tempfile
# import py7zr
import zipfile


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
    def get_md5(file):
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
        if self.get_md5(file1) == self.get_md5(file2):
            return True
        else:
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
        CommonFunCmd.subprocess_func("rpm2cpio {} | cpio -idm".format(os.path.basename(file)),
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

    def unpack(self, file, dir_name=""):
        if file.endswith(".tar.gz"):
            return self.deal_tgz(file, dir_name)
        elif file.endswith(".rpm"):
            return self.deal_rpm(file, dir_name)
        elif file.endswith(".zip"):
            return self.deal_zip(file, dir_name)

    def get_all_file(self, bate_path, path, elem=None):
        if elem is None:
            elem = []
        for root, ds, fs in os.walk(path):
            for f in fs:
                full_path = os.path.join(root, f)
                if full_path.endswith(".tar.gz") or full_path.endswith(".rpm") or full_path.endswith(".zip"):
                    self.get_all_file(bate_path, self.unpack(full_path), elem)
                else:
                    rela_path = full_path[len(bate_path):]
                    elem.append(rela_path)
        return elem

    def compare_dir(self, path1, path2):
        # base_path1 =
        files1 = self.get_all_file(path1, path1)
        files2 = self.get_all_file(path2, path2)

        set1 = set(files1)
        set2 = set(files2)

        common_files = set1 & set2

        for file in common_files:
            # if not self.compare_md5(os.path.join(path1, file), os.path.join(path2, file)):
            if not self.compare_md5(path1 + '/' + file, path2 + '/' + file):
                # TODO 不一致文件信息保存到文件
                self.same = False
                print("file {} is not same".format(file))

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

        return

    @staticmethod
    def pre_act(dir_name, file, path_name):
        if not os.path.exists(os.path.join(path_name, dir_name)):
            os.makedirs(os.path.join(path_name, dir_name))
        shutil.copy(file, os.path.join(path_name, dir_name))


def create_parser(args):
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--exclude", help="exclude file")


def main(args):
    unpack = Unpack(args)
    create_parser(args)
    if os.path.isfile(args[0]) and os.path.isfile(args[1]):
        is_same = unpack.compare_md5(args[0], args[1])
        if not is_same:
            path_dir1 = unpack.unpack(args[0], "unpack_tmp1")
            path_dir2 = unpack.unpack(args[1], "unpack_tmp2")
            unpack.compare_dir(path_dir1, path_dir2)
            shutil.rmtree(path_dir1)
            shutil.rmtree(path_dir2)
        if unpack.same:
            print("Two files are same!")
        else:
            print("Two files are not same!")

    else:
        logging.error("the arg is not a file!")


# 按间距中的绿色按钮以运行脚本。
if __name__ == '__main__':
    main(sys.argv[1:])
