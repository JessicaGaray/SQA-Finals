#  📌 Moira Denise P. Vasquez 📌
from selenium import webdriver
from selenium.webdriver.common.keys import Keys

options = webdriver.ChromeOptions()
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument('--incognito')
options.add_argument('--window-size=1024,768')

driver = webdriver.Chrome(options=options)
driver.get('http://207.148.91.197:5000/')
driver.save_screenshot('Scenario2Task1.png')
username = driver.find_element_by_name('username')
password = driver.find_element_by_name('password')

# Login
username.send_keys("maaagic")
driver.save_screenshot('Scenario2Task2.png')
password.send_keys("maaagic")
driver.save_screenshot('Scenario2Task3.png')
driver.find_element_by_class_name('btn-primary').click()
driver.save_screenshot('Scenario2Task4.png')

# LOGGING OUT
driver.find_element_by_tag_name('i').click()
driver.save_screenshot('Scenario2Task6.png')
driver.find_element_by_class_name('dropdown-item').click()
driver.save_screenshot('Scenario2Task7.png')
