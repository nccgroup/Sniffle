import RPi.GPIO as GPIO
import time
import logging
from threading import Thread

logger = logging.getLogger(__name__)

class Led(Thread):
    def __init__(self, channel_blue: int, channel_green: int, channel_red: int):
        Thread.__init__(self)
        # GPIO BOARD pin
        self.channel_blue = channel_blue
        self.channel_green = channel_green
        self.channel_red = channel_red
        self.channel_blue_state = False
        self.channel_green_state = False
        self.channel_red_state = False
        self.init_leds()

    def run(self):
        while True:
            if self.check_blue():
                self.blue_led_on()
                time.sleep(0.1)
            if self.check_green():
                self.green_led_on()
                time.sleep(0.1)
            if self.check_red():
                self.red_led_on()
                time.sleep(0.1)
            if self.check_off():
                self.leds_off()
                time.sleep(0.1)

    def init_leds(self):
        self.channel_blue_state = False
        self.channel_green_state = False
        self.channel_red_state = False
        GPIO.setup(self.channel_blue, GPIO.OUT)  # blue pin channel is set to output
        GPIO.setup(self.channel_green, GPIO.OUT)  # green pin channel is set to output
        GPIO.setup(self.channel_red, GPIO.OUT)  # red pin channel is set to output
        logger.info(f"Created LED")

    def blue_led_on(self):
        GPIO.output(self.channel_blue, GPIO.HIGH)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_green, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_red, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten

    def green_led_on(self):
        GPIO.output(self.channel_blue, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_green, GPIO.HIGH)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_red, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten

    def red_led_on(self):
        GPIO.output(self.channel_blue, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_green, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_red, GPIO.HIGH)  # LED-Pin auf High (+3.3V) setzen = einschalten

    def leds_off(self):
        GPIO.output(self.channel_blue, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_green, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten
        GPIO.output(self.channel_red, GPIO.LOW)  # LED-Pin auf High (+3.3V) setzen = einschalten

    def check_blue(self) -> bool:
        if self.channel_blue_state:
            return True

    def check_green(self) -> bool:
        if self.channel_green_state:
            return True

    def check_red(self) -> bool:
        if self.channel_red_state:
            return True

    def check_off(self) -> bool:
        if not self.channel_red_state and not self.channel_green_state and not self.channel_red_state:
            return True

    def set_blue(self):
        self.channel_blue_state = True
        self.channel_green_state = False
        self.channel_red_state = False

    def set_green(self):
        self.channel_blue_state = False
        self.channel_green_state = True
        self.channel_red_state = False

    def set_red(self):
        self.channel_blue_state = False
        self.channel_green_state = False
        self.channel_red_state = True

    def set_off(self):
        self.channel_blue_state = False
        self.channel_green_state = False
        self.channel_red_state = False

