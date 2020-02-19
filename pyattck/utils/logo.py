import os

from PIL import Image
from pyfiglet import Figlet

ASCII_CHARS = ['.',',',':',';','+','*','?','%','S','#','@']
ASCII_CHARS = ASCII_CHARS[::-1]

class Logo(object):

    """Generate or retrieve a logo for a given MITRE ATT&CK Actor or Group name
    
    Returns:
        str: The path to a image logo or string containing a generated ASCII text based on the Actor or Group name
    """    

    __DATA_PATH = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'actors'))

    def __init__(self, actor_name):
        self.image_path = None
        self.__check_for_logo(actor_name)

    def get_ascii(self):
        """Retrieve a ASCII string of an Actor or Group by name
        
        Returns:
            str: ASCII string of a generated logo
        """        
        return self.__image

    def get_image(self):
        """Retrieve a image logo path of an Actor or Group by name
        
        Returns:
            str: The path to the image logo of an Actor or Group by name
        """        
        if self.image_path:
            return self.image_path
        return None

    def __check_for_logo(self, actor_name):
        if os.path.exists('{}/{}.png'.format(self.__DATA_PATH, actor_name)):
            self.convert_image('{}/{}.png'.format(self.__DATA_PATH, actor_name))
            self.image_path = os.path.abspath('{}/{}.png'.format(self.__DATA_PATH, actor_name))
        else:
            custom_fig = Figlet(font='graffiti')
            self.__image = custom_fig.renderText(actor_name)

    def convert_image(self, path):
        image = None
        image = Image.open(path)
        self.__image = self.__process(image)

    def __resize(self, image, new_width=100):
        '''
        method resize():
            - takes as parameters the image, and the final width
            - resizes the image into the final width while maintaining aspect ratio
        '''
        (old_width, old_height) = image.size
        aspect_ratio = float(old_height)/float(old_width)
        new_height = int(aspect_ratio * new_width)
        new_dim = (new_width, new_height)
        new_image = image.resize(new_dim)
        return new_image
    
    def __gray_scale(self, image):
        '''
        method grayscalify():
            - takes an image as a parameter
            - returns the grayscale version of image
        '''
        return image.convert('L')

    def __modify(self, image, buckets=25):
        '''
        method modify():
            - replaces every pixel with a character whose intensity is similar
        '''

        initial_pixels = list(image.getdata())
        new_pixels = [ASCII_CHARS[pixel_value//buckets] for pixel_value in initial_pixels]
        return ''.join(new_pixels)

    def __process(self, image, new_width=100):

        '''
        method do():
            - does all the work by calling all the above functions
        '''

        image = self.__resize(image)
        image = self.__gray_scale(image)

        pixels = self.__modify(image)
        len_pixels = len(pixels)

        # Construct the image from the character list
        new_image = [pixels[index:index+new_width] for index in range(0, len_pixels, new_width)]

        return '\n'.join(new_image)
