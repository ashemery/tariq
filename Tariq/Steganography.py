'''
Copyright (C) 2010 Zachary Varberg
@author: Zachary Varberg

This file is part of Steganogra-py.

Steganogra-py is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Steganogra-py is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Steganogra-py.  If not, see <http://www.gnu.org/licenses/>.
'''
import Image

class FileTooLargeException(Exception):
    '''
    Custom Exception to throw if the file is too large to fit in 
    the Image file specified
    ''' 
    pass


def Dec2Bin(n):
    '''
    Function to convert an integer to a string of 1s and 0s that is the
    binary equivalent.  Code inspired from 
    http://www.daniweb.com/code/snippet216539.html
    '''
    return "".join([str((n>>y)&1) for y in xrange(7,-1,-1)])

def Bin2Dec(n):
    '''
    Function that takes a string of 1s and 0s and converts it back to an
    integer
    '''
    tmp = 0
    for i in xrange(1,len(n)+1):
        tmp+= (pow(2,i-1))*int(n[-i])
    return tmp

def encode(im_file, data_file, red_bits=1, green_bits=1, blue_bits=1):
    ''' 
    im_file is a string that is the file name of the image to 
    encode the data into.  The data comes from data_file (which is a file object or a StringIO).  Currently
    only character data is supported.  The red, green, and blue bits
    variables determine how many bits of each color to encode the data
    into.
    '''
    in_image = Image.open(im_file,'r')
    data = ""
    for line in data_file:
        for char in line:
            data += Dec2Bin(ord(char))
    # Termination characters
    data+= Dec2Bin(255) + Dec2Bin(255)
    
    new_image_data = []
    colors = ["red", "green", "blue"]
    i = 0;
    curCol = 0;
    for pixel in in_image.getdata():
        # This will hold the new array of R,G,B colors with the 
        # embedded data
        new_col_arr = []
        for color in pixel:
            new_col = 0
            # if we still have data to encode
            if(i < len(data)):
                
                # Number of bits to encode for this color
                bits = 1
                if (colors[curCol%3]=="red"):
                    bits = red_bits
                elif (colors[curCol%3]=="green"):
                    bits = green_bits
                elif (colors[curCol%3]=="blue"):
                    bits = blue_bits

                # Encode the number of bits requested
                tmp = list(Dec2Bin(color))
                for j in xrange(1,bits+1):
                    # if we still have data to encode
                    if(i < len(data)):
                        tmp[-j]=data[i]
                        i+=1
                
                #Pull out a new int value for the encoded color
                new_col = Bin2Dec("".join(tmp))
            else:
                new_col = color
            
            # Append the new color to our new pixel array
            new_col_arr.append(new_col)
            curCol +=1
        
        # Append the new 3 color array to our new image data
        new_image_data.append(new_col_arr)
    
    # If there wasn't enough pixels to encode all the data.
    if i != len(data):
        raise FileTooLargeException("Image to small for current settings.")

    # Write our new image data to a new image
    out_image = in_image.copy()
    for x in xrange(out_image.size[0]):
        for y in xrange(out_image.size[1]):
            pos = x + out_image.size[0] * y
            out_image.putpixel((x,y),tuple(new_image_data[pos]))
    return out_image
    
def decode(im_dec, red_bits=1, green_bits=1, blue_bits=1):
    in_image = Image.open(im_dec)

    # Number of consecutive ones to track if we've found the termination
    # characters
    num_ones = 0
    
    # The data pulled out
    data = []
    
    tmp_list = []
    colors = ["red", "green", "blue"]
    try:
        for pixel in in_image.getdata():
            i = 0
            for color in pixel:
                tmp = list(Dec2Bin(color))
                
                bits = 1
                if(colors[i%3]=="red"):
                    bits = red_bits
                if(colors[i%3]=="green"):
                    bits = green_bits
                if(colors[i%3]=="blue"):
                    bits = blue_bits

                # Pull out the specified number of bits based on the color
                for j in xrange(1,bits+1):
                    tmp_list.append(tmp[-j])
                    if tmp[-j] == '1':
                        num_ones += 1
                    else:
                        num_ones = 0
                    # If we have pulled out 1 byte of data
                    if len(tmp_list) == 8:
                        data.append(tmp_list)
                        tmp_list = []
                    # Two 255 characters is a termination sequence
                    if num_ones == 16:
                        raise StopIteration
                i += 1
                
    except StopIteration:
        pass
    
    
    chars = ""
    for char in data[:-1]:
        tmp = chr(Bin2Dec("".join(char)))
        if(ord(tmp)!=255):
            chars+=tmp
        
    return chars

def save_file(data, file_name):
    '''
    This will write all of the information in data (currently only
    character data is tested) and save it to the file file_name
    '''
    out_file = open(file_name,'wb+')
    out_file.write(data)
    out_file.close()

if __name__ == '__main__':
    pass
#    encode('flower.png','Macbeth.txt',0,1,6).save('newOut.png')
#    save_file(decode('newOut.png',0,1,6),'newOut1.txt')

