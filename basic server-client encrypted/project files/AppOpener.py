import os

class AppOpener:
    def open_url(url):
        if not url.startswith('www'):
            url = 'www.' + url
        os.system(f'start {url}')
    
    def open_app(app):
        os.system(f'start {app}.exe')
    
    def add_app(path):
        if os.path.isdir(path):
            os.system(f'setx path "%path%;{path}"')
            return True
        
        elif os.path.isfile(path):
            path = '/'.join(path.split('\\')[:-1])
            os.system(f'setx path "%path%;{path}"')
            return True
        
        return False
