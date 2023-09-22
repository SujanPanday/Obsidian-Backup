## Strings
```
┌──(kali㉿kali)-[~/python]
└─$ nano first.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat first.py 
#!/bin/python3

print("Hello, world!")
print('Hello, world!')
print("""This string runs
multiple lines!""")
print("This string is "+"awesome!") #we can also concatenate
print('\n') #new line 
print('Test that new line out.')
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 first.py
Hello, world!
Hello, world!
This string runs
multiple lines!
This string is awesome!


Test that new line out.

```

## Math
```
┌──(kali㉿kali)-[~/python]
└─$ nano second.py  
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat second.py   
#!/bin/python3

print(50 + 50) #add
print(50 - 50) #subtract
print(50 * 50) #multiply
print(50 / 50) #divide
print(50 + 50 - 50 * 50 / 50) #PEMDAS
print(50 ** 2) #exponents
print(50 % 6) #modulo - takes what is left over
print(50 / 6) #division with decimals
print(50 // 6) #no remainder
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 second.py 
100
0
2500
1.0
50.0
2500
2
8.333333333333334
8

```
## Variables & Methods
```
┌──(kali㉿kali)-[~/python]
└─$ python3 third.py 
  File "/home/kali/python/third.py", line 19
    print(int(30.9)) - Will it round? No!
                            ^^
SyntaxError: invalid syntax
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ nano third.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 third.py 
All is fair in love and war.
ALL IS FAIR IN LOVE AND WAR.
all is fair in love and war.
All Is Fair In Love And War.
28
33
30
30
My name is Heath and I am 33 years old.
34
35
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat third.py
#!/bin/python3

#Variables and Methods
quote = "All is fair in love and war."
print(quote)

print(quote.upper()) #uppercase
print(quote.lower()) #lowercase
print(quote.title()) #title case
print(len(quote)) #counts characters


name = "Heath" #string
age = 33 #int
gpa = 3.7 #float - has a decimal

print(int(age))
print(int(30.1))
print(int(30.9))

print("My name is " + name + " and I am " + str(age) + " years old.")


age +=1
print(age)

birthday = 1
age += birthday
print(age)
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 third.py
All is fair in love and war.
ALL IS FAIR IN LOVE AND WAR.
all is fair in love and war.
All Is Fair In Love And War.
28
33
30
30
My name is Heath and I am 33 years old.
34
35

```

## Functions
```
┌──(kali㉿kali)-[~/python]
└─$ nano fourth.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat fourth.py   
#!/bin/python3

#Functions
print("Here is an example function:")

def who_am_i(): #this is a function without parameters
        name = "Heath"
        age = 30 #local variable
        print("My name is " + name + " and I am " + str(age) + " years old.")

who_am_i()

#adding parameters
def add_one_hundred(num):
        print(num + 100)

add_one_hundred(100)

#multiple parameters
def add(x,y):
        print(x + y)

add(7,7)

def multiply(x,y):
        return x * y

multiply(7,7)
print(multiply(7,7))

def square_root(x):
        print(x ** .5)

square_root(64)


def nl():
        print('\n')

nl()
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 fourth.py 
Here is an example function:
My name is Heath and I am 30 years old.
200
14
49
8.0



```

## Boolean Expressions and Relational Operators
```
──(kali㉿kali)-[~/python]
└─$ cat fifth.py 
#!/bin/python3

#Boolean expressions (True or False)
print("Boolean expressions:")

bool1 = True
bool2 = 3*3 == 9
bool3 = False
bool4 = 3*3 != 9

print(bool1,bool2,bool3,bool4)
print(type(bool1))

bool5 = "True"
print(type(bool5))


#Relational and Boolean operators
greater_than = 7 > 5
less_than = 5 < 7
greater_than_equal_to = 7 >=7
less_than_equal_to = 7 <= 7

test_and = True and True #True
test_and2 = True and False #False
test_or = True or True #True
test_or2 = True or False #True

test_not = not True #False
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 fifth.py
Boolean expressions:
True True False False
<class 'bool'>
<class 'str'>

```

## Conditional Statements
```
┌──(kali㉿kali)-[~/python]
└─$ nano sixth.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat sixth.py 
#!/bin/python3

#Conditional Statements
def drink(money):
        if money >= 2:
                return "You've got yourself a drink!"
        else:
                return "No drink for you!"

print(drink(3))
print(drink(1))


def alcohol(age,money):
        if(age >= 21) and (money >= 5):
                return "We're getting a drink!"
        elif (age >= 21) and (money < 5):
                return "Come back with more money."
        elif (age < 21) and (money >= 5):
                return "Nice try, kid!"
        else:
                return "You're too poor and too young!"

print(alcohol(21,5))
print(alcohol(21,4))
print(alcohol(20,5))
print(alcohol(20,4))
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 sixth.py 
You've got yourself a drink!
No drink for you!
We're getting a drink!
Come back with more money.
Nice try, kid!
You're too poor and too young!
```


## Lists
```
┌──(kali㉿kali)-[~/python]
└─$ nano seventh.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat seventh.py 
#Lists - Have brackets []
movies = ["When Harry Met Sally", "The Hangover", "The Perks of Being a Wallflower", "The Exorcist"]

print(movies[1]) #returns the second item in the list - index / indices
print(movies[0]) #returns the first item in the list
print(movies[1:3]) #returns the first number given until right before last number given
print(movies[1:4]) #returns all 
print(movies[1:]) #returns everything from number to end of list
print(movies[:1]) #everything before 1
print(movies[:2])
print(movies[-1]) #grabs last item

print(len(movies)) #counts items in list
movies.append("JAWS")
print(movies) #appends to end of list

movies.insert(2, "Hustle")
print(movies)

movies.pop() #removes last item
print(movies)

movies.pop(0) #removes first item 
print(movies)

amber_movies = ['Just Go With It', '50 First Dates']
our_favorite_movies = movies + amber_movies
print(our_favorite_movies)

grades = [["Bob", 82], ["Alice", 90], ["Jeff", 73]]
bobs_grade = grades[0][1]
print(bobs_grade)
grades[0][1] = 83
print(bobs_grade)
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 seventh.py 
The Hangover
When Harry Met Sally
['The Hangover', 'The Perks of Being a Wallflower']
['The Hangover', 'The Perks of Being a Wallflower', 'The Exorcist']
['The Hangover', 'The Perks of Being a Wallflower', 'The Exorcist']
['When Harry Met Sally']
['When Harry Met Sally', 'The Hangover']
The Exorcist
4
['When Harry Met Sally', 'The Hangover', 'The Perks of Being a Wallflower', 'The Exorcist', 'JAWS']
['When Harry Met Sally', 'The Hangover', 'Hustle', 'The Perks of Being a Wallflower', 'The Exorcist', 'JAWS']
['When Harry Met Sally', 'The Hangover', 'Hustle', 'The Perks of Being a Wallflower', 'The Exorcist']
['The Hangover', 'Hustle', 'The Perks of Being a Wallflower', 'The Exorcist']
['The Hangover', 'Hustle', 'The Perks of Being a Wallflower', 'The Exorcist', 'Just Go With It', '50 First Dates']
82
82

```


## Tuples
```
┌──(kali㉿kali)-[~/python]
└─$ nano eight.py 
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat eight.py 
#!/bin/python3

#Tuples - Do not change, ()
grades = ("a", "b", "c", "d", "f")

#grades.pop, grades.append won't work - not mutable

print(grades[1])
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 eight.py
b
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ 

```

## Looping
```┌──(kali㉿kali)-[~/python]
└─$ nano ninth.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 ninth.py 
cucumber
spinach
cabbage
1
2
3
4
5
6
7
8
9
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat ninth.py 
#!/bin/python3

#For loops - start to finish of an iterate
vegetables = ["cucumber", "spinach", "cabbage"]
for x in vegetables:
        print(x)

#While loops - execute as long as true
i = 1

while i < 10:
        print(i)
        i += 1

```
## Importing Modules
```
┌──(kali㉿kali)-[~/python]
└─$ nano twelveth.py
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ cat twelveth.py 
#IMPORTING - Importing is important.
import sys #system functions and parameters
from datetime import datetime as dt #import with alias 

print(sys.version)
print(dt.now())
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 twelveth.py 
3.11.4 (main, Jun  7 2023, 10:13:09) [GCC 12.2.0]
2023-09-21 06:12:56.682606

```
## Advanced Strings
```
┌──(kali㉿kali)-[~/python]
└─$ cat tenth.py    
#!/bin/python3

#ADVANCED STRINGS

my_name = "Heath"
print(my_name[0]) #first letter
print(my_name[-1]) #last letter

sentence = "This is a sentence."
print(sentence[:4])

print(sentence.split()) #delimeter - default is a space

sentence_split = sentence.split()
sentence_join = ' '.join(sentence_split)
print(sentence_join)

quote = "He said, 'give me all your money'" #show example
quote = "He said, \"give me all your money\""
print(quote)

too_much_space = "                       hello          "
print(too_much_space.strip())

print("A" in "Apple") #returns true
print("a" in "Apple") #returns false - case sensitive

letter = "A"
word = "Apple"
print(letter.lower() in word.lower()) #improved

movie = "The Hangover"
print("My favorite movie is {}.".format(movie))
print("My favorite movie is %s" % movie)
print(f"My favorite movie is {movie}")
                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 tenth.py
H
h
This
['This', 'is', 'a', 'sentence.']
This is a sentence.
He said, "give me all your money"
hello
True
False
True
My favorite movie is The Hangover.
My favorite movie is The Hangover
My favorite movie is The Hangover
                                     
```

## Dictionaries
```
┌──(kali㉿kali)-[~/python]
└─$ cat eleventh.py 
#!/bin/python3

#DICTIONARIES - key/value pairs {}

drinks = {"White Russian": 7, "Old Fashion": 10, "Lemon Drop": 8} #drink is key, price is value
print(drinks)

employees = {"Finance": ["Bob", "Linda", "Tina"], "IT": ["Gene", "Louise", "Teddy"], "HR": ["Jimmy Jr.", "Mort"]}
employees['Legal'] = ["Mr. Frond"] #adds new key:value pair
print(employees)

employees.update({"Sales": ["Andie", "Ollie"]}) #adds new key:value pair
print(employees)

drinks['White Russian'] = 8
print(drinks)

print(drinks.get("White Russian"))

                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 eleventh.py 
{'White Russian': 7, 'Old Fashion': 10, 'Lemon Drop': 8}
{'Finance': ['Bob', 'Linda', 'Tina'], 'IT': ['Gene', 'Louise', 'Teddy'], 'HR': ['Jimmy Jr.', 'Mort'], 'Legal': ['Mr. Frond']}
{'Finance': ['Bob', 'Linda', 'Tina'], 'IT': ['Gene', 'Louise', 'Teddy'], 'HR': ['Jimmy Jr.', 'Mort'], 'Legal': ['Mr. Frond'], 'Sales': ['Andie', 'Ollie']}
{'White Russian': 8, 'Old Fashion': 10, 'Lemon Drop': 8}
8

```
## Sockets
```
┌──(kali㉿kali)-[~/python]
└─$ cat thirteen.py   
#!/bin/python3

#SOCKETS - Sockets can be used to connect two nodes together.  

import socket

HOST = '127.0.0.1'
PORT = 7777

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #af_inet is ipv4, sock stream is a port
s.connect((HOST,PORT))

                                                                                                                                                            
┌──(kali㉿kali)-[~/python]
└─$ python3 thirteen.py

┌──(kali㉿kali)-[~]
└─$ nc -lvnp 7777
listening on [any] 7777 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 37648

```
## Tool Building - Port Scanner
```
┌──(kali㉿kali)-[~]
└─$ nano fourtheen.py
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat fourtheen.py 
#!/bin/python3

import sys
import socket
from datetime import datetime

#Define our target
if len(sys.argv) == 2:
        target = socket.gethostbyname(sys.argv[1]) #Translate hostname to IPv4
else:
        print("Invalid amount of arguments.")
        print("Syntax: python3 scanner.py")

#Add a pretty banner
print("-" * 50)
print("Scanning target "+target)
print("Time started: "+str(datetime.now()))
print("-" * 50)

try:
        for port in range(50,85):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket.setdefaulttimeout(1)
                result = s.connect_ex((target,port)) #returns an error indicator - if port is open it throws a 0, otherwise 1
                if result == 0:
                        print("Port {} is open".format(port))
                s.close()

except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()

except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

except socket.error:
        print("Could not connect to server.")
        sys.exit()
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ python3 fourtheen.py 192.168.179.128
--------------------------------------------------
Scanning target 192.168.179.128
Time started: 2023-09-21 06:41:32.935229
--------------------------------------------------
```

## User Input 
```
┌──(kali㉿kali)-[~]
└─$ nano fifteen.py  
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat fifteen.py  
#!/bin/python3

#USER INPUT

x = float(input("Give me a number: "))
o = input("Give me an operator: ")
y = float(input("Give me yet another number: "))

if o == "+":
        print(x + y)
elif o == "-":
        print(x - y)
elif o == "/":
        print(x / y)
elif o == "*":
        print(x * y)
elif o == "**":
        print(x ** y)
else:
        print("Unknown operator.")
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ python3 fifteen.py                  
Give me a number: 3
Give me an operator: +
Give me yet another number: 45
48.0

```

## Reading and Writing Files
```
┌──(kali㉿kali)-[~]
└─$ python3 readwrite.py      
January
February
March
APril
May
June
July
August
September
October
November
December

                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat readwrite.py     
#!/bin/bash

months = open('months.txt')

print(months.read())

months.close()
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat months.txt      
January
February
March
APril
May
June
July
August
September
October
November
December

```
## Classes and Object
```──(kali㉿kali)-[~]
└─$ cat Employees.py 
#!/bin/python3

class Employees:

        def __init__(self, name, department, role, salary, years_employed):
                self.name = name
                self.department = department
                self.role = role
                self.salary = salary
                self.years_employed = years_employed

        def eligible_for_retirement(self):
                if self.years_employed >= 20:
                        return True
                else:
                        return False



                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ nano seventh.py
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat seventh.py     
#!/bin/python3

from Employees import Employees

e1 = Employees("Bob", "Sales", "Director of Sales", 100000, 20)
e2 = Employees("Linda", "Executive", "CIO", 150000, 10)

print(e1.name)
print(e2.role)
print(e1.eligible_for_retirement())
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ python3 seventh.py 
Bob
CIO
True
```

## Building a show budget too
```
┌──(kali㉿kali)-[~]
└─$ cat Shoes.py   
#!/bin/python3

class Shoes:
        def __init__(self, name, price):
                self.name = name
                self.price = float(price)
        
        def budget_check(self, budget):
                if not isinstance(budget, (int, float)):
                        print('Invalid entry. Please enter a number.')
                        exit()                
                    
        def change(self, budget):
                return (budget - self.price)
        
        def buy(self, budget):
                self.budget_check(budget)               
                            
                if budget >= self.price:
                        print(f'You can cop some {self.name}')
                        
                        if budget == self.price:
                                print('You have exactly enough money for these shoes.')
                        else:
                                print(f'You can buy these shoes and have ${self.change(budget)} left over')

                        exit('Thanks for using our shoe budget app!')
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat shoepurchase.py 
#!/bin/python3

from Shoes import Shoes

low = Shoes('And 1s', 30)
medium = Shoes('Air Force 1s', 120)
high = Shoes('Off Whites', 400)
 
try:
   shoe_budget = float(input('What is your shoe budget? '))
except ValueError:
   exit('Please enter a number')
  
for shoes in [high, medium, low]:
   shoes.buy(shoe_budget)
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ python3 shoepurchase.py 
What is your shoe budget? 44
You can cop some And 1s
You can buy these shoes and have $14.0 left over
Thanks for using our shoe budget app!

```
