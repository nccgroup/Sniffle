# source https://github.com/Rahul-RB/RotatingTextFile
import os
import io


class RotatingTextFile(io.TextIOWrapper):
    def __init__(
            self, file, condition, backupCount, mode="ab+", **kwargs):
        self.fp = open(file, mode)
        self.fileName = file
        self.condition = condition
        self.backupCount = backupCount

        super().__init__(
            self.fp,
            **kwargs
        )

    def write(self, line):
        # Custom pre-write algo:
        # Call condition, if it returns
        # true, then:
        # - rename all files from <name>.n-1 till <name>1
        # - copy original file over to <name>.1
        # - truncate original file
        # - write line into original file.
        # false, then:
        # - write line into original file.

        if self.condition:
            for i in range(self.backupCount - 1, 0, -1):
                try:
                    os.rename(self.fileName + "." + str(i), self.fileName + "." + str(i + 1))
                except FileNotFoundError as e:
                    pass
                except Exception as e:
                    raise e
            super().seek(0)
            lines = super().read()

            with open(self.fileName + ".1", "w") as fp:
                fp.write(lines)

            super().truncate(0)

        return super().write(line)

    def close(self):
        super().close()
        self.fp.close()