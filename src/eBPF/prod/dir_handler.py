import re
from helper.file import File
from helper.dir import Dir

from helper import helper
from helper import scripts


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'



class DIR_handler():

    self.root = None
    
    def __init__(self):
        self.root = helper.create_fake_dir_data_helper()

    def cmd(self, cmd, username="", src_dir="", target_dir=""):

        output = None

        src_dir = src_dir or self.fake_cwd


        cmd_name = cmd.split(" ")[0]
        args = cmd.split(" ")[1:]

        if cmd.startswith("bash./"):
            output = self.bash(cmd[6:].split(), src_dir)
        else:
            match cmd_name:
                case "ls":
                    output = self.ls(args, src_dir)
                case "rm":
                    output = self.rm(args, src_dir)
                case "touch":
                    output = self.touch(args, src_dir)
                case "cat":
                    output = self.cat(args, src_dir)
                case ("echo" | "echo/bin/echo"):
                    output = self.echo(args, src_dir)

        return output

    def cat(self, args, src_dir):
        target_file = ""
        src_dir_list = helper.path_to_list_helper(src_dir)
        target_file, args_str = helper.get_main_arg_helper(args)
        if "/" in target_file:
            target_file, src_dir_list = helper.target_dir_is_path_helper(target_file, src_dir_list)
    
        if not target_file:
            output = ""
            return output
    
        src_obj = self.root
    
        if src_dir_list != []:
            for layer in src_dir_list:
                src_obj = src_obj.content[layer]
        try:
            target_obj = src_obj.content[target_file]
        except KeyError:
            return f"cat: '{target_file}': No such file or directory"
        if target_obj.file_type == "directory":
            return f"cat: '{target_file}': Is a directory"
        
        file_content = target_obj.filecontent
    
        def protect_quotes(match):
            return match.group(0).replace("\n", " ")  # Entferne Zeilenumbrüche innerhalb von '...'
    
        file_content = re.sub(r"'(.*?[^\\])'", protect_quotes, file_content, flags=re.DOTALL)
    
        return file_content


    def echo(self, args, src_dir):
        target_file = ""
        if len(args) == 0:
            return "\n"
        else:
            if '>>' in args or '>' in args:
                if len(args) > 2 and args[-2] in [">", ">>"]:
                    new_file_content = " ".join(arg.replace('"', '').replace("'", "") for arg in args[:-2])
                    src_dir_list = helper.path_to_list_helper(src_dir)                    
                    target_file, args_str = helper.get_main_arg_helper(args)
                    target_file = args[-1]
                    if "/" in target_file:
                        target_file, src_dir_list = helper.target_dir_is_path_helper(target_file, src_dir_list)
                    src_obj = self.root
                    if src_dir_list != []:
                        for layer in src_dir_list:
                            src_obj = src_obj.content[layer]
                    if args[-2] == ">":
                        try:
                            target_obj = src_obj.content[target_file]
                            
                            target_obj.filecontent = new_file_content
                            return ""
                        except KeyError:
                            return f"-bash: '{target_file}': No such file or directory"
                    elif args[-2] == ">>":
                        try:
                            target_obj = src_obj.content[target_file]
                            
                            target_obj.filecontent = target_obj.filecontent + "\n" + new_file_content
                            return ""
                        except KeyError:
                            return f"-bash: '{target_file}': No such file or directory"
                        
                else:
                    return "-bash: syntax error near unexpected token `newline'"
            return " ".join(arg.replace('"', '').replace("'", "") for arg in args) + "\n"

        
        

    def ls(self, args, src_dir):
        output = ""
        target_dir = ""
        src_dir_list = helper.path_to_list_helper(src_dir)

        target_dir, args_str = helper.get_main_arg_helper(args)

        if "/" in target_dir:
            target_dir, src_dir_list = helper.target_dir_is_path_helper(target_dir, src_dir_list)

        src_obj = self.root

        if src_dir_list != []:
            for layer in src_dir_list:
                src_obj = src_obj.content[layer]

        if target_dir:
            try:
                target_obj = src_obj.content[target_dir]
            except KeyError:
                return f"ls: cannot access '{target_dir}': No such file or directory"
        else:
            target_obj = src_obj

        if target_obj.file_type != "directory":
            output = target_obj.name

        else:
            l = "l" in args_str
            a = "a" in args_str
            r = "r" in args_str

            if l:
                target_obj_parent = target_obj.parent
                output += f"{target_obj.perm} {target_obj.xxx} {target_obj.owner} {target_obj.group} {target_obj.size} {target_obj.created_month} {target_obj.created_day} {target_obj.created_time} "
                output += bcolors.OKBLUE + f"{'.'}\n" + bcolors.ENDC

                output += f"{target_obj_parent.perm} {target_obj_parent.xxx} {target_obj_parent.owner} {target_obj_parent.group} {target_obj_parent.size} {target_obj_parent.created_month} {target_obj_parent.created_day} {target_obj_parent.created_time} "
                output += bcolors.OKBLUE + f"{'..'}\n" + bcolors.ENDC

            for file in target_obj.content:
                print_obj = target_obj.content[file]
                is_dir = print_obj.file_type == "directory"

                if not a and file.startswith("."):
                    continue

                if l:
                    output += f"{print_obj.perm} {print_obj.xxx} {print_obj.owner} {print_obj.group} {print_obj.size} {print_obj.created_month} {print_obj.created_day} {print_obj.created_time} "

                    if is_dir: output += bcolors.OKBLUE
                    output += f"{file}\n"
                    if is_dir: output += bcolors.ENDC

                else:
                    if is_dir: output += bcolors.OKBLUE
                    output += file + " "
                    if is_dir: output += bcolors.ENDC

            output = output.strip("\n ")

            if r:
                output_list = output.split("\n" if l else " ")
                output_list.reverse()

                join_char = "\n" if l else " "
                output = join_char.join(output_list)

                # TODO Temp fix for color magic bytes being reversed
                output = output.replace(bcolors.OKBLUE, "")
                output = output.replace(bcolors.ENDC, "")

        return output

    def bash(self, args, src_dir):
        target_file = ""
        src_dir_list = helper.path_to_list_helper(src_dir)
        target_file, args_str = helper.get_main_arg_helper(args)
 
        if "/" in target_file:
            target_file, src_dir_list = helper.target_dir_is_path_helper(target_file, src_dir_list)
 
        if not target_file:
            return "./: missing file operand\nTry './ --help' for more information."
 
        '''src_obj = self.root
        if src_dir_list != []:
            for layer in src_dir_list:
                if layer not in src_obj.content:
                    return f"./: cannot access '{target_file}': No such file or directory"
                src_obj = src_obj.content[layer]'''

        try:
            src_obj = helper.navigate_to_path(self.root, src_dir_list)
        except KeyError:
            return f"./: cannot access '{target_file}': No such file or directory"
 
        try:
            target_obj = src_obj.content[target_file]
        except KeyError:
            return f"./: cannot execute '{target_file}': No such file or directory"
 
        if target_obj.file_type != "file":
            return f"./: {target_file}: Is not a file"
 
        if not target_obj.perm.startswith("-rwx"):
            return f"./: {target_file}: Permission denied"

        try:
            script_content = target_obj.filecontent
        
            
            protected_content = []
            def protect_quotes(match):
                protected_content.append(match.group(0))
                return f"__PROTECTED_{len(protected_content) - 1}__"
            
            script_content = re.sub(r"'(.*?[^\\])'", protect_quotes, script_content, flags=re.DOTALL)
            
            lines = script_content.splitlines() 
            if lines and lines[0].startswith("#!"):
                lines = lines[1:]
            output = []
            for i in range(len(lines)):
                for idx, content in enumerate(protected_content):
                    lines[i] = lines[i].replace(f"__PROTECTED_{idx}__", content)
                if lines[i] != "" or lines[i] != " ":
                    cmd_output = scripts.execute_command(self, lines[i], src_dir)
                if cmd_output != "":
                    output.append(cmd_output)
            output.append("\n")
            return output
        except Exception as e:
            return f"./: {target_file}: Error during processing: {str(e)}"


    def rm(self, args, src_dir):
        target_file = ""
        src_dir_list = helper.path_to_list_helper(src_dir)

        target_file, args_str = helper.get_main_arg_helper(args)

        if "/" in target_file:
            target_file, src_dir_list = helper.target_dir_is_path_helper(target_file, src_dir_list)

        if not target_file: 
            output = "rm: missing operand \nTry 'rm --help' for more information."
            return output

        src_obj = self.root

        if src_dir_list != []:
            for layer in src_dir_list:
                src_obj = src_obj.content[layer]

        try:
            target_obj = src_obj.content[target_file]
        except KeyError:
            return f"rm: cannot remove '{target_file}': No such file or directory"

        r = "r" in args_str
        f = "f" in args_str

        if not r and target_obj.file_type == "directory":
            return

        src_obj.content.pop(target_file)

        return None



    def touch(self, args, src_dir):
        target_file = ""
        path_flag = False

        target_file, _ = helper.get_main_arg_helper(args)

        if "/" in target_file:
            path_flag = True
            target_file, src_dir_list = helper.target_dir_is_path_helper(target_file, src_dir)

        if not target_file: 
            output = "touch: missing file operand \nTry 'touch --help' for more information."
            return output 

        file_type_split = target_file.split(".")

        if len(file_type_split) > 1:
            file_type = target_file.split(".")[-1]
        else:
            file_type = "file"

        target_obj = File(target_file, file_type=file_type)

        helper.add_file_helper(self.root, src_dir_list if path_flag else src_dir, target_obj)

        return ""


