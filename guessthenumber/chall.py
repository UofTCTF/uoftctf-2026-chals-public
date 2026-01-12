#!/usr/local/bin/python3
import random
from ast import literal_eval

MAX_NUM = 1<<100
QUOTA = 50

def evaluate(exp, x):
    if isinstance(exp, int) or isinstance(exp, bool):
        return exp
    if isinstance(exp, str):
        if exp == 'x':
            return x
        else:
            raise ValueError("Invalid variable")
    if not isinstance(exp, dict):
        raise ValueError("Invalid expression")
    
    match exp['op']:
        case "and":
            return evaluate(exp['arg1'], x) and evaluate(exp['arg2'], x)
        case "or":
            return evaluate(exp['arg1'], x) or evaluate(exp['arg2'], x)
        case ">":
            return evaluate(exp['arg1'], x) > evaluate(exp['arg2'], x)
        case ">=":
            return evaluate(exp['arg1'], x) >= evaluate(exp['arg2'], x)
        case "<":
            return evaluate(exp['arg1'], x) < evaluate(exp['arg2'], x)
        case "<=":
            return evaluate(exp['arg1'], x) <= evaluate(exp['arg2'], x)
        case "+":
            return evaluate(exp['arg1'], x) + evaluate(exp['arg2'], x)
        case "-":
            return evaluate(exp['arg1'], x) - evaluate(exp['arg2'], x)
        case "*":
            return evaluate(exp['arg1'], x) * evaluate(exp['arg2'], x)
        case "/":
            return evaluate(exp['arg1'], x) // evaluate(exp['arg2'], x)
        case "**":
            return evaluate(exp['arg1'], x) ** evaluate(exp['arg2'], x)
        case "%":
            return evaluate(exp['arg1'], x) % evaluate(exp['arg2'], x)
        case "not":
            return not evaluate(exp['arg1'], x)
        

wins = 0
x = random.randint(0, MAX_NUM)
for i in range(QUOTA):
    expression = literal_eval(input(f"Input your expression ({i}/{QUOTA}): "))
    if bool(evaluate(expression, x)):
        print("Yes!")
    else:
        print("No!")

guess = int(input("Guess the number: "))
if guess == x:
    print("Yay you won! Here is the flag: ")
    print(open("flag.txt", 'r').read())
else:
    print("Wrong. Good luck next time.")