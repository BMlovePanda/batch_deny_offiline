from pandas import json_normalize
import json, requests,re
from lib.log import autodeny_log

logger = autodeny_log('autoenablepolicy.log').getlog()


def load_denied_ip_list(api_url, auth_key):
    """获取ads已封堵ip地址，用于与提交的ip地址进行过滤"""
    logger.debug(f"获取{api_url}已封堵IP地址。")
    s = requests.session()
    data = {
        'auth_key': auth_key,
        'target': 'divertManual',
        'action_type': 'load'
    }
    result = s.post(api_url, data=data, verify=False).text
    #设备返回的内容中，会在封堵描述或其他地方多出了DivertManual字样，导致无法转换成json，目前怀疑是设备bug导致
    result = json.loads(result.replace("DivertManual", ""))
    logger.debug(result)
    df_result = json_normalize(result['data'])
    ads_ip = re.findall('\d+\.\d+\.\d+\.\d+', api_url)[0]
    logger.debug(f"ads:{ads_ip},当前已封堵IP地址:{len(df_result)}个")
    return df_result


def load_deny_hash(api_url, auth_key):
    """封堵时需要提交设备侧获取的hash，获取设备侧最新hash"""
    logger.info("获取封堵hash。")
    s = requests.session()
    data = {
        'auth_key': auth_key,
        'target': 'divertManual',
        'action_type': 'gethash'
    }
    result = s.post(api_url, data=data, verify=False).json()['hash']
    logger.debug(result)
    return result


def auto_deny(api_url, auth_key, deny_data_json):
    """以json格式提交封堵数据"""
    s = requests.session()
    act_hash = load_deny_hash(api_url, auth_key)
    data = {
        'auth_key': auth_key,
        'target': 'divertManual',
        'action_type': 'add',
        'hash': act_hash,
        'configs': deny_data_json
    }
    logger.info("提交封堵数据")
    res = s.post(api_url, data=data, verify=False).json()
    if res['result'] == 'success':
        logger.info("本轮完成封堵,封堵成功。")
        result = "封堵成功"
    else:
        logger.error(f"本轮完成封堵,封堵失败，失败原因:{res['content']['actionErrors']}。")
        result = f"封堵失败，失败原因:{res['content']['actionErrors']}。"
    return result