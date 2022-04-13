import threading
import time
import RPi.GPIO as GPIO

GPIO.setmode(GPIO.BOARD) # Use physical pin numbering

class Button(threading.Thread):
    def __init__(self, channel):
        threading.Thread.__init__(self)
        self.pressed = False
        self.channel = channel
        GPIO.setup(self.channel, GPIO.IN)
        self.deamon = True
        self.start()

    def run(self):
        previous = None
        while 1:
            current = GPIO.input(self.channel)
            time.sleep(0.01)

            if current is False and previous is True:
                self.pressed = True

                while self.pressed:
                    time.sleep(0.05)

            previous = current

def on_button_press(self):
    print("btn pressed")
