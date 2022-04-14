import RPi.GPIO as GPIO
import time
from threading import Thread

GPIO.setmode(GPIO.BOARD)

class Button(Thread):
    def __init__(self, channel):
        Thread.__init__(self)
        self.channel = channel
        self.pressed = False
        GPIO.setup(channel, GPIO.IN, pull_up_down=GPIO.PUD_UP)

    def run(self):
        while True:
            input_state = GPIO.input(self.channel)
            if not input_state:
                if self.pressed:
                    self.pressed = False
                else:
                    self.pressed = True
                print(f"Button Pressed: {self.pressed}")
                time.sleep(0.2)

    def get_button_state(self) -> bool:
        return self.pressed