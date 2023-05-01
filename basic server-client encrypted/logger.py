import logging
from logging.handlers import SocketHandler

class Logger:
    def __init__(self, debugging_mode = False, logger_name = 'Root'):
        self.root_logger = logging.getLogger(logger_name)
        self.root_logger.setLevel(1)  
        self.socket_handler = SocketHandler('127.0.0.1', 19996) 
        self.root_logger.addHandler(self.socket_handler)
        self.root_logger.info('logger started')
        self.loggers = {'Root':self.root_logger}
        self.debugging_mode = debugging_mode
    
    def create_logger(self, name:str, parent_logger = 'Root'):
        if name not in self.loggers and parent_logger in self.loggers:
            self.loggers[name] = self.loggers[parent_logger].getChild(name)
    
    def log_info(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].info(log)
    
    def log_warning(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].warning(log)
    
    def log_error(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].error(log)
    
    def log_critical(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers:
            self.loggers[logger_name].critical(log)
    
    def log_debug(self, log:str, logger_name = 'Root'):
        if logger_name in self.loggers and self.debugging_mode:
            self.loggers[logger_name].debug(log)
    
    def log(self, log:str, log_type:str = 'info', logger_name = 'Root'):
        log_type = log_type.lower()
        if log_type == 'critical':
            self.log_critical(log=log, logger_name=logger_name)
        if log_type == 'error':
            self.log_error(log=log, logger_name=logger_name)
        if log_type == 'warning':
            self.log_warning(log=log, logger_name=logger_name)
        if log_type == 'info':
            self.log_info(log=log, logger_name=logger_name)
        if log_type == 'debug':
            self.log_debug(log=log, logger_name=logger_name)

def main():
    logger = Logger(debugging_mode=True)
    print(type(logger))
    logger.create_logger('sub')
    print(type(logger))
    logger.log_debug('test')
    logger.log_info('test', 'sub')
    logger.create_logger('sub sub', 'sub')
    logger.log_critical('test2', 'sub sub')
    logger.log_error('test2', 'sub sub')
    logger.log_warning('test2', 'sub sub')
  
if __name__ == "__main__":
    main()