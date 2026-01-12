import os
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def _chrome_driver() -> webdriver.Chrome:
    options = Options()
    options.add_argument("--headless=true")
    # give me ur 0day pls
    options.add_argument("--no-sandbox")

    chrome_bin = os.environ.get("CHROME_BIN", "/usr/local/bin/chromium")
    chromedriver_bin = os.environ.get("CHROMEDRIVER_BIN", "/usr/local/bin/chromedriver")

    if chrome_bin and os.path.exists(chrome_bin):
        options.binary_location = chrome_bin
    if chromedriver_bin and os.path.exists(chromedriver_bin):
        service = Service(executable_path=chromedriver_bin)
        return webdriver.Chrome(service=service, options=options)

    return webdriver.Chrome(options=options)


def run_admin_bot(target_url: str) -> None:
    base = "http://127.0.0.1:5000"
    admin_pw = os.environ.get("ADMIN_PASSWORD")
    if not admin_pw:
        raise RuntimeError("ADMIN_PASSWORD missing")

    driver = _chrome_driver()
    try:
        driver.set_page_load_timeout(10)
        driver.set_script_timeout(10)
        driver.get(f"{base}/motd")
        WebDriverWait(driver, 5).until(
            EC.presence_of_element_located((By.XPATH, "//h1[normalize-space()='Message of the Day']"))
        )
        driver.get(f"{base}/login")
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.NAME, "username")))
        driver.find_element(By.NAME, "username").send_keys("admin")
        driver.find_element(By.NAME, "password").send_keys(admin_pw)
        driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
        WebDriverWait(driver, 5).until(EC.presence_of_element_located((By.ID, "inbox-page")))
        driver.get(f"{base}/flag")
        WebDriverWait(driver, 5).until(EC.text_to_be_present_in_element((By.TAG_NAME, "body"), "OK"))
        driver.get(target_url)
        time.sleep(10)
    finally:
        driver.quit()
