import RPi.GPIO as GPIO
import logging
import sys
import signal

logger = logging.getLogger(__name__)

def signal_handler(sig, frame):
    GPIO.cleanup()
    sys.exit(0)


class Button:
    def __init__(self, channel, name):
        self.channel = channel
        self.name = name
        self.pressed = False
        GPIO.setmode(GPIO.BOARD)
        GPIO.setup(self.channel, GPIO.IN, pull_up_down=GPIO.PUD_UP)

        GPIO.add_event_detect(self.channel, GPIO.BOTH,
                              callback=self.button_callback, bouncetime=50)

        signal.signal(signal.SIGINT, signal_handler)
        logger.info(f"Created button '{self.name}' thread on gpio channel: {self.channel}. Initial state: {self.pressed}")

    def button_callback(self, channel):
        # button released:
        if GPIO.input(self.channel):
            if not self.pressed:
                self.pressed = True
                logger.info(f"Button '{self.name}' pressed, state: {self.pressed}")
            else:
                self.pressed = False
                logger.info(f"Button '{self.name}' pressed, state: {self.pressed}")

    def get_button_state(self) -> bool:
        return self.pressed