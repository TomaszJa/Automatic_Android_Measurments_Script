from threading import Thread
from time import sleep
import os
import subprocess
import sys
import re
from datetime import datetime
import xml.etree.ElementTree as ET

host = "20.50.64.23"
# host = "192.168.0.10 and port 8001"
# host = "192.168.0.22 and port 45455"
tshark_path = "D:/Wireshark/Tshark.exe"
#tshark_path = "C:\Program Files\Wireshark"
interface = "Ethernet"
iterations = 220


def get_dump():
    os.system(f'adb shell uiautomator dump')
    sleep(0.1)
    os.system(f'adb pull /sdcard/window_dump.xml')
    sleep(0.1)

def restart_app():
    back()
    back()
    back()
    sleep(1)
    os.system("adb shell am force-stop com.example.oauth2testingapp")
    sleep(3)
    os.system("adb shell am start -n com.example.oauth2testingapp/com.example.oauth2testingapp.MainActivity")
    sleep(10)

def __check_xml__(child, text, result):
    if (text == child.attrib["text"]) and child.attrib["clickable"] == "true":
        result.append(child)
    if text == child.attrib["content-desc"]:
        result.append(child)
    if text == child.attrib["resource-id"]:
        result.append(child)
    for grandchild in child:
        __check_xml__(grandchild, text, result)


def get_text_coordinate(text, index=0):
    result = []
    i = 5
    while not result:
        i -= 1
        if i < 0:
            break
        get_dump()
        tree = ET.parse('window_dump.xml')
        root = tree.getroot()
        for child in root:
            __check_xml__(child, text, result)
    if result:
        data = result[index].attrib['bounds']
        coordinate = re.findall("\[(\d+)\,(\d+)\]\[(\d+)\,(\d+)\]", data)[0]
        print(coordinate)
        x = int((int(coordinate[0]) + int(coordinate[2])) * 0.5)
        y = int((int(coordinate[1]) + int(coordinate[3])) * 0.5)
        return x, y
    else:
        restart_app()
        return None,None


def click_on_text(text, index=0):
    x, y = get_text_coordinate(text, index)
    print(x, y)
    if x:
        os.system(f'adb shell input tap %s %s' % (x, y))
        return True
    return False


def click_on_point(coordinates):
    x, y = coordinates
    print(x, y)
    if x and y:
        os.system(f'adb shell input tap %s %s' % (x, y))
        return True
    return False


def start_client_credentials():
    t = Thread(target=asyncRun,
               args=(f'{tshark_path} -i {interface} -f "host {host}" -w client_credentials.pcap',))
    t.start()
    textfile = open("client_credentials_timestamps.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        timestamps = []
        print(f"Test {i+1} of {iterations}")
        timestamps.append(f"Test {i}")
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("CLIENT CREDENTIALS"):
            continue
        sleep(0.2)
        if not click_on_text("LOG OUT"):
            continue
        sleep(0.2)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("client_credentials_timestamps.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")


def input_text(text):
    os.system(f"adb shell input text '{text}'")


def back():
    os.system("adb shell input keyevent 4")


def asyncRun(command):
    os.system(command)


def start_ropc():
    sleep(1)
    t = Thread(target=asyncRun, args=(f'{tshark_path} -i {interface} -f "host {host}" -w ropc.pcap',))
    t.start()
    textfile = open("ropc_timestamps.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        timestamps = []
        print(f"Test {i+1} of {iterations}")
        timestamps.append(f"Test {i}")
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("RESOURCE OWNER PASSWORD CREDENTIALS"):
            continue
        sleep(0.2)
        if not click_on_text("Username"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        sleep(0.2)
        if not click_on_text("Password"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        sleep(0.2)
        timestamps.append(f"Login: {str(datetime.now())}")
        if not click_on_text("LOG IN"):
            continue
        sleep(0.2)
        timestamps.append(f"Logout: {str(datetime.now())}")
        if not click_on_text("LOG OUT"):
            continue
        sleep(0.2)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("ropc_timestamps.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")


def get_ropc_coordinates():
    ropc_cd = {}
    sleep(0.5)
    ropc_cd["ROPC"] = get_text_coordinate("RESOURCE OWNER PASSWORD CREDENTIALS")
    click_on_point(ropc_cd["ROPC"])
    sleep(0.5)
    ropc_cd["Username"] = get_text_coordinate("Username")
    click_on_point(ropc_cd["Username"])
    input_text("admin")
    back()
    ropc_cd["Password"] = get_text_coordinate("Password")
    click_on_point(ropc_cd["Password"])
    input_text("admin")
    back()
    ropc_cd["LOG_IN"] = get_text_coordinate("LOG IN")
    click_on_point(ropc_cd["LOG_IN"])
    sleep(0.5)
    ropc_cd["LOG_OUT"] = get_text_coordinate("LOG OUT")
    click_on_point(ropc_cd["LOG_OUT"])
    sleep(0.5)
    ropc_cd["BACK_TO_MAIN"] = get_text_coordinate("BACK TO THE MAIN PAGE")
    click_on_point(ropc_cd["BACK_TO_MAIN"])

    return ropc_cd

def swipe_up():
    os.system("adb shell input swipe 1000 2000 1000 1000")

def start_auth_code():
    t = Thread(target=asyncRun, args=(f'{tshark_path} -i {interface} -f "host {host}" -w auth_code_with_openID.pcap',))
    t.start()
    textfile = open("auth_code_with_openID_timestamps.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        print(f"Test {i+1} of {iterations}")
        timestamps = []
        timestamps.append(f"Test {i}")
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("AUTH CODE FLOW"):
            continue
        sleep(1)
        if not click_on_text("Username"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        if not click_on_text("Password"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        timestamps.append(f"Login: {str(datetime.now())}")
        if not click_on_text("Login"):
            continue
        sleep(1)
        swipe_up()
        if not click_on_text("Remember My Decision"):
            continue
        sleep(0.2)
        timestamps.append(f"Confirmation: {str(datetime.now())}")
        if not click_on_text("Yes, Allow"):
            continue
        sleep(1)
        timestamps.append(f"Logout: {str(datetime.now())}")
        if not click_on_text("LOG OUT"):
            continue
        sleep(1)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("auth_code_with_openID_timestamps.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")

def start_auth_code_no_openID():
    t = Thread(target=asyncRun, args=(f'{tshark_path} -i {interface} -f "host {host}" -w auth_code_no_openID.pcap',))
    t.start()
    textfile = open("auth_code_no_openID_timestamps.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        print(f"Test {i+1} of {iterations}")
        timestamps = []
        timestamps.append(f"Test {i}")
        sleep(1)
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("AUTH CODE FLOW"):
            continue
        sleep(3)
        if not click_on_text("Username"):
            continue
        sleep(1)
        input_text("admin")
        sleep(1)
        back()
        if not click_on_text("Password"):
            continue
        sleep(1)
        input_text("admin")
        sleep(1)
        back()
        timestamps.append(f"Login: {str(datetime.now())}")
        if not click_on_text("Login"):
            continue
        sleep(2)
        swipe_up()
        if not click_on_text("Remember My Decision"):
            continue
        sleep(1)
        timestamps.append(f"Confirmation: {str(datetime.now())}")
        if not click_on_text("Yes, Allow"):
            continue
        sleep(2)
        timestamps.append(f"Logout: {str(datetime.now())}")
        if not click_on_text("LOG OUT"):
            continue
        sleep(2)
        timestamps.append(f"Confirm logout: {str(datetime.now())}")
        if not click_on_text("Yes"):
            continue
        sleep(2)
        timestamps.append(f"Return to app: {str(datetime.now())}")
        if not click_on_text("com.android.chrome:id/close_button"):
            continue
        sleep(2)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("auth_code_no_openID_timestamps.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")

def start_implicit():
    t = Thread(target=asyncRun, args=(f'{tshark_path} -i {interface} -f "host {host}" -w implicit_with_openID.pcap',))
    t.start()
    textfile = open("implicit_with_openID_timestamps.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        print(f"Test {i+1} of {iterations}")
        timestamps = []
        timestamps.append(f"Test {i}")
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("IMPLICIT FLOW"):
            continue
        sleep(1)
        if not click_on_text("Username"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        if not click_on_text("Password"):
            continue
        sleep(0.2)
        input_text("admin")
        sleep(0.2)
        back()
        timestamps.append(f"Login: {str(datetime.now())}")
        if not click_on_text("Login"):
            continue
        sleep(1)
        swipe_up()
        if not click_on_text("Remember My Decision"):
            continue
        sleep(0.2)
        timestamps.append(f"Confirmation: {str(datetime.now())}")
        if not click_on_text("Yes, Allow"):
            continue
        sleep(1)
        timestamps.append(f"Logout: {str(datetime.now())}")
        if not click_on_text("LOG OUT"):
            continue
        sleep(1)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("implicit_with_openID_timestamps.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")
    
def start_implicit_no_openID():
    t = Thread(target=asyncRun, args=(f'{tshark_path} -i {interface} -f "host {host}" -w implicit_no_openID.pcap',))
    t.start()
    textfile = open("implicit_timestamps_no_openID.txt", "w")
    textfile.write("")
    textfile.close()
    i = 0
    while i < iterations:
        print(f"Test {i+1} of {iterations}")
        sleep(1)
        timestamps = []
        timestamps.append(f"Test {i}")
        timestamps.append(f"Flow Start: {str(datetime.now())}")
        if not click_on_text("IMPLICIT FLOW"):
            continue
        sleep(3)
        if not click_on_text("Username"):
            continue
        sleep(1)
        input_text("admin")
        sleep(1)
        back()
        if not click_on_text("Password"):
            continue
        sleep(1)
        input_text("admin")
        sleep(1)
        back()
        timestamps.append(f"Login: {str(datetime.now())}")
        if not click_on_text("Login"):
            continue
        sleep(2)
        swipe_up()
        if not click_on_text("Remember My Decision"):
            continue
        sleep(1)
        timestamps.append(f"Confirmation: {str(datetime.now())}")
        if not click_on_text("Yes, Allow"):
            continue
        sleep(2)
        timestamps.append(f"Logout: {str(datetime.now())}")
        if not click_on_text("LOG OUT"):
            continue
        sleep(2)
        timestamps.append(f"Confirm logout: {str(datetime.now())}")
        if not click_on_text("Yes"):
            continue
        sleep(2)
        timestamps.append(f"Return to app: {str(datetime.now())}")
        if not click_on_text("com.android.chrome:id/close_button"):
            continue
        sleep(2)
        if not click_on_text("BACK TO THE MAIN PAGE"):
            continue
        timestamps.append(f"Flow End: {str(datetime.now())}")
        textfile = open("implicit_timestamps_no_openID.txt", "a")
        for element in timestamps:
            textfile.write(element + "\n")
        textfile.close()
        i += 1
    os.system("taskkill /f /im  Tshark.exe")


if __name__ == '__main__':
    start_auth_code()
    start_implicit()
    start_client_credentials()
    start_ropc()
    # start_implicit_no_openID()
    # start_auth_code_no_openID()
    exit()

