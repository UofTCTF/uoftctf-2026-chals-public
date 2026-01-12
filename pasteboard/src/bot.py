import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

BASE_URL = "http://127.0.0.1:5000"
FLAG = "uoftctf{n0_c00k135_n0_pr0bl3m_1m40_122c3466655003ca64d689e3ee0e786d}"

def visit_url(target_url):
    options = Options()
    options.add_argument("--headless=true")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(target_url)
        time.sleep(30)
    finally:
        driver.quit()
