import logging,time,os
from logging.handlers import RotatingFileHandler
class autodeny_log(object):
    def __init__(self,logfilename,logger = None):
        '''
            指定保存日志的文件路径，日志级别，以及调用文件
            将日志存入到指定的文件中
        '''
        # 创建一个logger
        self.logger = logging.getLogger(logger)
        self.logger.handlers.clear()
        self.logger.setLevel(logging.DEBUG)
        # 创建一个handler，用于写入日志文件
        self.log_time = time.strftime("%Y_%m_%d_")
        self.log_path = os.path.split(os.path.realpath(__file__))[0] + '/log/'
        if not os.path.exists( self.log_path):
            os.makedirs(self.log_path)
        self.log_name = logfilename
        self.log_file = self.log_path + self.log_name
        fh = RotatingFileHandler(self.log_file,maxBytes = 4*1024*1024,backupCount = 3)
        fh.setLevel(logging.DEBUG)


        # 定义handler的输出格式
        #formatter = logging.Formatter('[%(asctime)s] %(filename)s->%(funcName)s line:%(lineno)d [%(levelname)s]%(message)s')
        formatter = logging.Formatter(
            '[%(asctime)s][%(levelname)s]%(message)s'
        )
        fh.setFormatter(formatter)
        #屏幕输出handler
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(formatter)

        # 给logger添加handler
        self.logger.addHandler(fh)
        self.logger.addHandler(ch)
        # 关闭打开的文件
        fh.close()
        ch.close()
    def getlog(self):
        return self.logger