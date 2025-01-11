from helper import helper

class SYSTEM_handler:

    def __init__(self, username="") -> None:
        self.username = username

    def cmd(self, cmd, username=None):
        output = None

        if username:
            self.username = username

        cmd_name = cmd.split(" ")[0]
        args = cmd.split(" ")[1:]

        match cmd_name:
            case "whoami":
                output = self.whoami()
            case "w":
                output = self.w()
            case "id":
                output = self.id()

        return output

    def whoami(self):
        return self.username

    def w(self):
        return helper.create_fake_w_helper(self.username)

    def id(self):
        return helper.create_fake_id_helper(self.username)
