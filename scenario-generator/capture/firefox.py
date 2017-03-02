#!/usr/bin/env python3
from selenium import webdriver
from xvfbwrapper import Xvfb
from selenium.webdriver.common.desired_capabilities import DesiredCapabilities
import sys

display = Xvfb()
display.start()

profile = webdriver.FirefoxProfile()

if len(sys.argv) != 2:
    sys.stderr.write("Invalid argument count\n")
    sys.exit(1)

profile.set_preference("browser.newtabpage.enabled", False)
profile.set_preference("browser.newtabpage.enhanced", False)
profile.set_preference("browser.newtabpage.introShown", False)
profile.set_preference("browser.newtabpage.directory.ping", "")
profile.set_preference("browser.newtabpage.directory.source", "data:application/json,{}")
profile.set_preference("browser.newtab.preload", False)
profile.set_preference("toolkit.telemetry.reportingpolicy.firstRun", False)

webdriver = webdriver.Firefox(profile)
webdriver.get('http://' + sys.argv[1])
webdriver.quit()

display.stop()
