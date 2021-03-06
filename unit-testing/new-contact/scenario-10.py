## Alzona, Jeremy

from pyvirtualdisplay import Display
from selenium import webdriver

display = Display(visible=0, size=(1920, 1080))
display.start()

options = webdriver.ChromeOptions()
options.add_argument('--no-sandbox')
options.add_argument('--headless')
options.add_argument('--incognito')
options.add_argument('--window-size=1920,1080')

driver = webdriver.Chrome(chrome_options=options)
driver.get('http://207.148.91.197:5000/')
driver.save_screenshot('Scenario10Task1.png')
driver.find_element_by_name('username').send_keys('automate')
driver.find_element_by_name('password').send_keys('automate')
driver.save_screenshot('Scenario10Task2.png')
driver.find_element_by_css_selector("[type='submit']").click()
driver.save_screenshot('Scenario10Task3.png')
driver.find_element_by_css_selector("[data-target='#new-contact']").click()
driver.save_screenshot('Scenario10Task4.png')
driver.find_element_by_name('firstname').send_keys('Scenario 2')
driver.save_screenshot('Scenario10Task5.png')
driver.find_element_by_id("add-contact-btn").click()
driver.save_screenshot('Scenario10Task6.png')

driver.quit()
display.sendstop()
