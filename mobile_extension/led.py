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
        self.colour = 0 # 0: off, 1: blue; 2: green, 3 = red
        self.target_colour = 0
        self.sniffer_running = False
        self.init_leds()

    def run(self):
        while True:
            if self.target_colour is not self.colour:
                self.set_color()

    def init_leds(self):
        self.colour = 0 # off
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


    def set_blue(self):
        self.target_colour = 1

    def set_green(self):
        self.target_colour = 2

    def set_red(self):
        self.target_colour = 3

    def set_off(self):
        self.target_colour = 0

    def set_blue_state(self):
        self.colour = 1

    def set_green_state(self):
        self.colour = 2

    def set_red_state(self):
        self.colour = 3

    def set_off_state(self):
        self.colour = 0

    def set_color(self):
        if self.target_colour == 1:
            self.set_blue_state()
            self.blue_led_on()
        if self.target_colour == 2:
            self.set_green_state()
            self.green_led_on()
        if self.target_colour == 3:
            self.set_red_state()
            self.red_led_on()
        if self.target_colour == 0:
            self.set_off_state()
            self.leds_off()

    def indicate_successful(self):
        self.set_off()
        time.sleep(.2)
        self.set_green()
        time.sleep(.1)
        self.set_off()
        time.sleep(.1)
        self.set_green()
        time.sleep(.1)
        self.set_off()
        time.sleep(.1)
        self.set_green()
        time.sleep(.1)
        self.set_off()
        time.sleep(.3)

    def indicate_failure(self):
        self.set_off()
        time.sleep(.2)
        self.set_red()
        time.sleep(.1)
        self.set_off()
        time.sleep(.1)
        self.set_red()
        time.sleep(.1)
        self.set_off()
        time.sleep(.1)
        self.set_red()
        time.sleep(.1)
        self.set_off()
        time.sleep(.3)