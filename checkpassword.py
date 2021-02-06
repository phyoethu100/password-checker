import requests
import hashlib
import sys
import string
import tkinter.ttk
from random import *
from tkinter import *
from PIL import Image, ImageTk

BG_COLOR = "#%02x%02x%02x" % (230, 243, 255)

def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char 
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}, check the api and try again.")
    return res

def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def generate_password():
    characters = string.ascii_letters + string.punctuation  + string.digits
    password =  "".join(choice(characters) for x in range(randint(8, 14)))
    return password 

def main(args):
    row_count1 = 4
    row_count2 = 4

    mycolor0 = "#%02x%02x%02x" % (51, 102, 153)
    heading = Label(text="Password Checker Results", fg=mycolor0, bg=BG_COLOR)
    heading.grid(column=1, row=0)
    heading.config(font=("Arial", 28, "bold"))

    heading = Label(text="", bg=BG_COLOR)
    heading.grid(column=1, row=1)

    image = Image.open("password.jpg")
    image = image.resize((80, 60), Image.ANTIALIAS)
    photo = ImageTk.PhotoImage(image)

    password_image = Label(image=photo)
    password_image.image = photo # this line need to prevent gc
    password_image.grid(column=0, row=0)
    
    mycolor1 = "#%02x%02x%02x" % (255, 77, 77) 
    result1 = Label(text="You might want to change your password!", fg=mycolor1, bg=BG_COLOR)
    result1.grid(column=0, row=2)
    result1.config(font=("Arial", 18, "bold"))

    result1 = Label(text="", bg=BG_COLOR)
    result1.grid(column=0, row=3)

    image2 = Image.open("thumb_up.jpg")
    image2 = image2.resize((90, 60), Image.ANTIALIAS)
    photo2 = ImageTk.PhotoImage(image2)

    thumb_up = Label(image=photo2)
    thumb_up.image = photo2 # this line need to prevent gc
    thumb_up.grid(column=2, row=0)

    mycolor2 = "#%02x%02x%02x" % (0, 179, 89)
    result2 = Label(text="You can keep your password!", fg=mycolor2, bg=BG_COLOR)
    result2.grid(column=2, row=2)
    result2.config(font=("Arial", 18, "bold"))

    result2 = Label(text="", bg=BG_COLOR)
    result2.grid(column=2, row=3)

    separator_row = 1

    for password in args:
        count = pwned_api_check(password)
        separator_row += 3

        tkinter.ttk.Separator(window, orient=VERTICAL).grid(column=1, row=2, rowspan=separator_row, sticky='ns')
     
        if count:
            row_count1 += 1
            lines = Label(text="", bg=BG_COLOR)
            lines.grid(column=1, row=row_count1)

            mycolor3 = "#%02x%02x%02x" % (0, 172, 230)
            bad_password = Label(text=f"{password} was found {count} times...", fg=mycolor3, bg=BG_COLOR)
            bad_password.grid(column=0, row=row_count1)
            bad_password.config(font=("Verdana", 14, "bold"))

            mycolor4 = "#%02x%02x%02x" % (46, 184, 184)
            new_password = Label(text=f"Here is a suggested password: {generate_password()}", fg=mycolor4, bg=BG_COLOR)
            new_password.grid(column=0, row=row_count1+1)
            new_password.config(font=("Verdana", 14))

            blank_line = Label(text="", bg=BG_COLOR)
            blank_line.grid(column=0, row=row_count1+2)
            row_count1 += 2
      
        else:
            row_count2 += 1
            mycolor5 = "#%02x%02x%02x" % (255, 148, 77)
            good_password = Label(text=f"{password} was not found...", fg=mycolor5, bg=BG_COLOR)
            good_password.grid(column=2, row=row_count2)
            good_password.config(font=("Verdana", 14, "bold"))
            row_count2 += 1
    
    return "Done!"


if __name__ == "__main__":

    window = Tk()
    window.title("Password Checker")
    window.config(padx=30, pady=30)  
    window.configure(bg=BG_COLOR)

    main(sys.argv[1:])
    
    window.mainloop()
