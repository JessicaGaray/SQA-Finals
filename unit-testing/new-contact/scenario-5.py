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
driver.save_screenshot('Scenario5Task1.png')
driver.find_element_by_name('username').send_keys('automate')
driver.find_element_by_name('password').send_keys('automate')
driver.save_screenshot('Scenario5Task2.png')
driver.find_element_by_css_selector("[type='submit']").click()
driver.save_screenshot('Scenario5Task3.png')
driver.find_element_by_css_selector("[data-target='#new-contact']").click()
driver.save_screenshot('Scenario5Task4.png')
driver.find_element_by_name('firstname').send_keys("Scenario 5: Sh~;?RAE*O'dQuiDv^|^4MD6:sMJVJkgE@us0},\TFGoVwS95A$RLck&b?Yp/9;%-64L6%NXD%}v1S}tuh|qBeT6FGZZu-!o,5YZtO9Hnqt]/$.,w>a€:Eo|=@i<KoEi:VUKsy@N0H-@5!!AmEU4s,.A@d['pT(UksMq<65MxcEvkPNp%*^@ol1E=YaStMRTcf")
driver.save_screenshot('Scenario5Task5.png')
driver.find_element_by_id("add-contact-btn").click()
driver.save_screenshot('Scenario5Task6.png')

driver.quit()
display.sendstop()
