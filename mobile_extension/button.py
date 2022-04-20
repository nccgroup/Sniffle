import RPi.GPIO as GPIO
import time
from threading import Thread
import logging
from logging.handlers import QueueHandler # DONT DELETE!!!


logger = logging.getLogger(__name__)

# Callback: GPIO add event detect-> rising falling waitforedge

class Button(Thread):
    def __init__(self, channel, name):
        Thread.__init__(self)
        self.channel = channel
        self.name = name
        self.pressed = False
        GPIO.setup(channel, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        logger.info(f"Created button '{self.name}' thread on gpio channel: {self.channel}. Initial state: {self.pressed}")

    def run(self):
        while True:
            input_state = GPIO.input(self.channel)
            if not input_state:
                if self.pressed:
                    self.pressed = False
                else:
                    self.pressed = True
                logger.info(f"Button '{self.name}' pressed, state: {self.pressed}")
                time.sleep(0.2)

    def get_button_state(self) -> bool:
        return self.pressed