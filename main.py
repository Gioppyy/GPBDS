from utils import FolderScanner
from utils import logger, input_utils

def main():
    print(r"""
 _____ __________________  _____
|  __ \| ___ \ ___ \  _  \/  ___|
| |  \/| |_/ / |_/ / | | |\ `--.
| | __ |  __/| ___ \ | | | `--. \
| |_\ \| |   | |_/ / |/ / /\__/ /
 \____/\_|   \____/|___/  \____/
""")

    server_path = input_utils.get_arg("path", "./")
    logger.info(f"Server path: {server_path}")

    logs = []
    fscanner = FolderScanner(logger, server_path)
    logs.extend(fscanner.scan())

    if len(logs) > 0:
        logger.warn(f"Found {len(logs)} entries, check the opened browser")
    else:
        logger.info("No entreis found.")

if __name__ == "__main__":
    main()
