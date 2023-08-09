import pandas as pd
import os, sys
import requests
from datetime import datetime
from lib.log import autodeny_log
from IPy import IP
from lib.deny_api import auto_deny, load_denied_ip_list
import sqlite3

pd.options.mode.chained_assignment = None
requests.packages.urllib3.disable_warnings()
logger = autodeny_log('autodeny.log').getlog()

def check_api():
    api_list = get_sql("select api_url from api_config where id<=3;")
    s = requests.session()
    for i in api_list:
        try:
            res = s.get(i[0],timeout=3,verify=False)
            if res.status_code !=200:
                result = 1
                logger.error("大佬，封堵API网络异常，你是不是没有使用Openvpn呀！")
                return -1
        except:
            logger.error("大佬，封堵API网络异常，你是不是没有使用Openvpn呀！")
            return -1
    logger.info("大佬，封堵API网络正常，来，我们干死红队。")
    return 0

def ip_format(x):
    try:
        result = IP(x['待封堵IP'])
        ip_format = result.strNormal()
        ip_version = result.version()
    except:
        ip_format = x['待封堵IP']
        ip_version = "格式错误"
    x['待封堵IP'] = ip_format
    x['ip_type'] = ip_version
    return x


def get_sql(sql_query):
    conn = sqlite3.connect("./sqlite3.db")
    cursor = conn.cursor()
    cursor.execute(sql_query)
    result = cursor.fetchall()
    cursor.close()
    return result


def filter_white_ip(x, white_list):
    """判断封堵IP是否为省内地址"""
    for i in white_list:
        if IP(x['待封堵IP']) in IP(i[0]):
            result = "否，省内地址，封了会出故障的，大佬。"
            break
        else:
            result = "是"
    return result


def filter_deny_ip(df_ip_list):
    """
        1、待封堵IP地址去重；
        2、根据已封堵IP剔除已封堵IP地址；
        3、根据ads的v6和v4封堵能力以及ads已封堵数据进行封堵ads选择；
        4、根据白名单IP剔除不应封堵的IP，例如自有公网地址；
    """
    logger.info("根据白名单、已封堵IP进行重复及不应封堵地址剔除。")
    df_ip_list = df_ip_list.apply(ip_format, axis=1)
    df_ip_list.drop_duplicates(subset='待封堵IP', inplace=True)
    white_list = get_sql("select ip_segment from white_list")
    df_ip_list['是否封堵'] = df_ip_list.apply(filter_white_ip,
                                          args=(white_list, ),
                                          axis=1)
    ads_denied_list = []
    ads_api_config = get_sql(
        "select api_url,auth_key,deny_ipv6 from api_config")
    for i in ads_api_config:
        ads_denied_list.append(load_denied_ip_list(i[0], i[1]))
    df_ads_denied = pd.concat(ads_denied_list)
    result = pd.merge(df_ip_list,
                      df_ads_denied,
                      left_on='待封堵IP',
                      right_on='ip',
                      how='left')
    result['是否封堵'].mask(result['ip'].notna(), '否，重复封堵', inplace=True)
    logger.info(
        f"完成处理，共{len(result[result['是否封堵']=='是'])}个IP需要封堵。"
    )
    return result[['待封堵IP', 'ip_type', '是否封堵']]


def create_deny_data(df_deny_ip, api_id):
    deny_data_template = get_sql(
        f"select dst,daemon,extend,status,mask,api_url,auth_key from api_config where id={api_id}"
    )
    df_deny_ip[[
        'dst', 'daemon', 'extend', 'status', 'mask', 'api_url', 'auth_key'
    ]] = list(deny_data_template[0])
    df_deny_ip['description'] = f"{datetime.now():%Y-%m-%d}批量封堵"
    return df_deny_ip


def main():
    logger.info("检查封堵API网络状态，大佬请稍后。")
    if check_api() !=0:
        return -1
    workdir = os.path.split(os.path.abspath(__file__))[0]
    input_file_name = "批量封堵IP清单模板.xlsx"
    deny_ip_list_file = workdir + "/" + input_file_name
    df_all_ip = pd.read_excel(deny_ip_list_file)
    if df_all_ip.empty:
        logger.error("大佬，你整个空表干球啥呢，仔细一点。")
        return -1
    logger.info(f"本次提交封堵总IP数量:{len(df_all_ip)}个。")
    if len(df_all_ip) <= 50:
        logger.info(f"红队没吃饭么，就这么点攻击？")
    else:
        logger.info(f"大佬牛逼，监测到如此多的攻击IP，干死红队！")
    need_deny_ip_list = filter_deny_ip(df_all_ip)
    if need_deny_ip_list[need_deny_ip_list['是否封堵'] == '是'].empty:
        logger.error("大佬，没有IP地址可以封，不要逗我，好么？？")
        return -1
    deny_ipv4 = need_deny_ip_list[(need_deny_ip_list['ip_type'] == 4)
                                  & (need_deny_ip_list['是否封堵'] == '是')]
    deny_ipv6 = need_deny_ip_list[(need_deny_ip_list['ip_type'] == 6)
                                  & (need_deny_ip_list['是否封堵'] == '是')]
    split_size = 101
    logger.info(f"封堵中，大佬喝杯茶，请稍后。")
    for i in range(0, len(deny_ipv4), split_size):
        split_df_v4 = deny_ipv4.loc[i:i + split_size - 1, :]
        api_id = i % 3 + 1
        deny_data_v4 = create_deny_data(split_df_v4, api_id)
        deny_data_v4.rename(columns={'待封堵IP': 'ip'}, inplace=True)
        auto_deny(
            deny_data_v4['api_url'].values[0],
            deny_data_v4['auth_key'].values[0], deny_data_v4[[
                'ip', 'dst', 'daemon', 'extend', 'status', 'mask',
                'description'
            ]].to_json(orient='records'))
    for j in range(0, len(deny_ipv6), split_size):
        split_df_v6 = deny_ipv6.loc[j:j + split_size - 1, :]
        api_id = j % 2 + 4
        deny_data_v6 = create_deny_data(split_df_v6, api_id)
        deny_data_v6.rename(columns={'待封堵IP': 'ip'}, inplace=True)
        auto_deny(
            deny_data_v6['api_url'].values[0],
            deny_data_v6['auth_key'].values[0], deny_data_v6[[
                'ip', 'dst', 'daemon', 'extend', 'status', 'mask',
                'description'
            ]].to_json(orient='records'))
    return 0

if __name__ == "__main__":
    os.system('clear')
    banner="""
 _____           _      ____          _ _____                    
|  ___|   _  ___| | __ |  _ \ ___  __| |_   _|__  __ _ _ __ ___  
| |_ | | | |/ __| |/ / | |_) / _ \/ _` | | |/ _ \/ _` | '_ ` _ \ 
|  _|| |_| | (__|   <  |  _ <  __/ (_| | | |  __/ (_| | | | | | |
|_|   \__,_|\___|_|\_\ |_| \_\___|\__,_| |_|\___|\__,_|_| |_| |_|
                                    code by Paulownia     2023.08
注意:请配合VPN使用
"""
    print(banner)
    logger.info("====================程序开始====================")
    
          
        
    if main() == 0:

        logger.info("====================运行结束====================")
    else:
        logger.error("====================运行错误====================")