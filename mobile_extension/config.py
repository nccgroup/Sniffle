import os

import yaml
import logging
from os import walk

logger = logging.getLogger(__name__)


class Config:
    def __init__(self, config_path: str):
        """config_path: root directory of usb flash.
        The filename must contain 'config', '.yml' file extension required
        and be place at root dir of usb flash drive"""
        filenames = next(walk(config_path), (None, None, []))[2]  # [] if no file
        for filename in filenames:
            if "config" in filename:
                if  ".yml" in filename:
                    # sanitize:
                    if ".txt" in filename:
                        filename_path = config_path + '/' + filename
                        sanitized_filename_path = config_path + '/' + filename.removesuffix(".txt")
                        os.rename(filename_path, sanitized_filename_path)
                        logger.info(f"Sanitized {filename_path} to {sanitized_filename_path}")
                        filename = filename.removesuffix(".txt")
                    config_path = config_path + "/" + filename
                    with open(config_path, 'r') as stream:
                        try:
                            self.config_dictionary = yaml.safe_load(stream=stream)
                        except yaml.YAMLError as exception:
                            logger.error("Error while loading config.", exc_info=True)
                            raise exception
                else:
                    logger.error(f"Not able to load Config file: '{filename}'. No '.yml' file extension.")
            else:
                logger.error(f"Cannot load config file: {filename}. The filename must contain 'config', '.yml' file extension required and be place at root dir of usb flash drive.")

    def init_config(self, config_path: str):
        self.__init__(self, config_path)

    def get_config(self) -> dict:
        return self.config_dictionary

    def save_config(self, save_config_path: str):
        """saves the dictionary to save_config_path"""
        with open(save_config_path, 'w') as outfile:
            try:
                yaml.dump(self.config_dictionary, outfile, default_flow_style=False)
                logger.info(f"Config saved to <{save_config_path}>")
            except yaml.YAMLError as exception:
                logger.error(f"Error while writing config to {save_config_path}", exc_info=True)
                raise exception

