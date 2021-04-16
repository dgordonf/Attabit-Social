import pygame
import time
import PySimpleGUI as sg
import re
from nltk import ngrams

pygame.font.init()
screen = pygame.display.set_mode((1800,900))
background = "#fffaf0"
screen.fill((background))
myfont = pygame.font.Font(None, 90)

s = "Life is short, as everyone knows. When I was a kid I used to wonder about this. Is life actually short, or are we really complaining about its finiteness? Would we be just as likely to feel life was short if we lived 10 times as long? Since there didn't seem any way to answer this question, I stopped wondering about it. Then I had kids. That gave me a way to answer the question, and the answer is that life actually is short. Having kids showed me how to convert a continuous quantity, time, into discrete quantities. You only get 52 weekends with your 2 year old. If Christmas-as-magic lasts from say ages 3 to 10, you only get to watch your child experience it 8 times. And while it's impossible to say what is a lot or a little of a continuous quantity like time, 8 is not a lot of something. If you had a handful of 8 peanuts, or a shelf of 8 books to choose from, the quantity would definitely seem limited, no matter what your lifespan was."

n = 3
grammys = ngrams(s.split(), n)


for gram in grammys:
    text = " ".join(gram)
    text = myfont.render(text,1,"#0d0d0d")
    screen.blit(text, (300,300))
    pygame.display.update()
    time.sleep(0.3)
    screen.fill((background))
    pygame.display.update()
time.sleep(1)
pygame.display.quit()