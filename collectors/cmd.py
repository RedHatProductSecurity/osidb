import logging
import subprocess  # nosec: B404

logger = logging.getLogger(__name__)


class Cmd:
    @staticmethod
    def run(
        command, stdin="", fail_silently=False, log_stdout=False, cwd=None, shell=True
    ):
        logger.debug(f"Running command {command}")
        # Only fixed (string) commands are run by default, but injection via arguments may still occur
        # For example, if (dynamic) filenames contain shell metacharacters
        # f"xsltproc {outfile}", where outfile == "myfile.xml; rm -r /bin"
        # becomes "xsltproc myfile.xml; rm -r /bin". Shouldn't be exploitable
        # because we usually call with fixed arguments, so there's no user-provided / injectable data to escape
        # Use shell=False with a list of arguments if you want to guarantee safe behavior regardless
        # https://security.stackexchange.com/questions/221565/are-alphanumeric-strings-safe-to-pass-to-a-bash-script
        result = subprocess.run(  # nosec: B602
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=stdin,
            encoding="utf-8",
            shell=shell,
            cwd=cwd,
        )

        if result.stdout and log_stdout:
            logger.debug(f"stdout was: {result.stdout}")
        if result.stderr:
            logger.debug(f"stderr was: {result.stderr}")
        if not fail_silently and (result.returncode or result.stderr):
            raise RuntimeError(
                f"Command Execution failed. command='{command}', "
                f"status='{result.returncode}, stderr='{result.stderr}', "
                f"stdout='{result.stdout}'"
            )
        return result
