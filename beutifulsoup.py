import requests
from bs4 import BeautifulSoup
from openpyxl import Workbook
from openpyxl import load_workbook

URL = "https://cwe.mitre.org/data/definitions/200"
page = requests.get(URL)
soup = BeautifulSoup(page.content, "html.parser")
target_style='display:inline; margin:0px 0px 2px 0px; vertical-align: text-bottom'
element = soup.find("h2", {"style": target_style})
print((element.text).lstrip(':'))                                        #title print
stuffs = soup.find_all("div", class_="title")

if stuffs:
    for stuff in stuffs:
        weakness=stuff.find("div", style="font-weight:bold", string=lambda t: t and "Weakness ID:" in t)
        if weakness:
            print(weakness.text.split("Weakness ID:")[-1].strip())
        else:
            print('Weakness id not found')                                #weakness print
        vulnmap= soup.find_all('span',class_='tool')
        if vulnmap: 
            for vuln in vulnmap[:2]:
                if vuln:
                    first_child_span = vuln.find('span')
                    print(first_child_span.text) 
        else:
            print('vulnmap not found')              
Description=soup.find('div',id='Description')  
if Description:
    indent_div=Description.find('div',class_='indent')
    print(indent_div.text) 
else:
    print('description not found')                                           #desc print
ext_desc=soup.find('div',id='Extended_Description')  
if ext_desc:
    indent_div1=ext_desc.find('div',class_='indent')
    print(indent_div1.text) 
    print('')                                              #ext desc print
    print('')
else:
    print('extended description not found') 
alt_terms=soup.find('div',id='Alternate_Terms') 
if alt_terms:
    tr_element = alt_terms.find_all('tr')
    for i in tr_element:
        th=i.find('th')
        print(th.text)
else:
    print('alternate terms not found')  

mitigations=soup.find('div',id='Potential_Mitigations') 
if mitigations:
    tr_element = mitigations.find_all('tr')
    for i in tr_element:
        p=i.find('p')
        print(p.text)
else:
    print('mititgations terms not found')  

intro=soup.find('div',id='Modes_Of_Introduction')
if intro:
    div2=intro.find('div',class_='expandblock')
    div3=div2.find('div',class_='tabledetail')
    indent=div3.find('div',class_='indent')
    table=indent.find('table',id='Detail')
    th_elements = []
    for tr in table:
        for th in tr:           
            th_elements.append(th.string)
    lastfour=th_elements[2::2] 
    for a in lastfour:
        if a:
            print(a)     

langtech=soup.find('div',id='Applicable_Platforms')                         #platform lang,tech
if langtech:
    expandblock=langtech.find('div',class_='expandblock')
    if expandblock:    
     detail=expandblock.find('div',class_='detail')
     if detail:    
         ind=detail.find('div',class_='indent')
         subheadings = ind.find_all('p', class_='subheading')
         for subheading in subheadings:
            if subheading.text == 'Languages':
            
                next_sibling = subheading.find_next_sibling()
                while next_sibling and next_sibling.name == 'div' and 'indent' in next_sibling.get('class', []):
                    print(next_sibling.text)
                    next_sibling = next_sibling.find_next_sibling()
            elif subheading.text == 'Technologies':
            
                next_sibling = subheading.find_next_sibling()
                while next_sibling and next_sibling.name == 'div' and 'indent' in next_sibling.get('class', []):
                    print(next_sibling.text)
                    next_sibling = next_sibling.find_next_sibling()


likelihood=soup.find('div',id='Likelihood_Of_Exploit')                         #platform lang,tech
if likelihood:
    expandblock2=likelihood.find('div',class_='expandblock')
    if expandblock2:
        detail_div=expandblock2.find('div',class_='detail')  
        if detail_div:
            whatwewant=detail_div.find('div')
            if whatwewant:
                print(whatwewant.text)                                       
else:print('Likelihood of exploit not found')
obeservedex=soup.find('div',id='Observed_Examples')                      
if obeservedex:  
    expandblock3=obeservedex.find('div',class_='expandblock')
    if expandblock3:   
        tabledetail=expandblock3.find('div',class_='tabledetail')  
        if tabledetail:
            indent_div2=tabledetail.find('div',class_='indent')
            if indent_div2:
                div4=indent_div2.find('div')
                table2=div4.find('table')
                tr1=table2.find_all('tr')
                for a in tr1:
                    td1=a.find('td')
                    if td1:
                        div5=td1.find('div')
                        print(div5.text)
else:print('Observed Examples not found')                        
print('')
print('')   

detectionmethod=soup.find('div',id='Detection_Methods')                      
if detectionmethod:  
    expandblock4=detectionmethod.find('div',class_='expandblock')
    if expandblock4:   
        div6=expandblock4.find('div',class_='detail')
        if div6:
            indent_div3=div6.find('div',class_='indent')
            if indent_div3:
                grouped=indent_div3.find('div',id='Grouped')
                if grouped:
                    tabledetail2=grouped.find('table')
                    for tr6 in tabledetail2.find_all('tr'):
                        td2=tr6.find('td')
                        if td2:
                            p2=td2.find('p',class_='subheading')
                            print(p2.text)
else:print('Detection Methods not found')



def save_to_excel(rows,output):
    workbook=Workbook()
    sheet=workbook.active
    sheet.title='Empty Cells'
    for row in rows:
        sheet.append(row)
    workbook.save(output)  
    print(f'Data saved to {output}')