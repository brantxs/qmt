use base64::{engine::general_purpose, Engine};
use chrono::Local;
use core::result::Result as C_Result;
use csv::StringRecord;
use encoding_rs::Encoding;
use env_logger::Env;
use env_logger_pipe::PIPE;
use log::{debug, error, info, LevelFilter};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::CryptoRngCore;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;
use std::borrow::Cow;
use std::fs::File;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::Duration;

mod config;
mod env_logger_pipe;

// static global_encode: Lazy<Option<&Encoding>> = Lazy::new(|| {
//    let gbk_encoding: Option<&Encoding> = Encoding::for_label("GBK".as_bytes());
//    gbk_encoding
//});

// 委托结构
#[derive(Debug)]
struct WtRecord {
    stock_id: String,
    stock_name: String,
    _price: i32,
    count: String,
    //time: String,
    flag: String,
    status: String,
    order_num: String,
    comments: String,
}

#[derive(Debug)]
struct StockOp {
    stock_id: String,
    oper_type: String,
    target_price: usize,
    target_amount: usize,
    stock_name: String,
    target_price_ori: String,
    id: String,
    comments: String,
}

#[derive(Debug)]
struct StockCC {
    stock_id: String,
    stock_name: String,
    amount: String,
    holding_cost: String,
    status: String,
    remain: usize,
    flag: usize,
}

#[derive(Debug)]
struct ZhInfo {
    stock_capitalization: f64,
    available_balance: f64,
    total_asset: f64,
    freeze_balance: f64,
}

fn main() {
    // 初始化日志
    // 设置默认级别为info
    let env = Env::default().filter_or("QMT_LOG_LEVEL", "info");

    let pp = Box::new(PIPE::new(true).expect("初始化日志输出失败"));

    let mut b = env_logger::Builder::from_env(env);
    b.target(env_logger::Target::Pipe(pp));
    b.format(|buf, record| {
        writeln!(
            buf,
            "{}:{} {} [{}] - {}",
            record.file().unwrap_or("unknown"),
            record.line().unwrap_or(0),
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            &record.args()
        )
    });
    b.init();

    // 初始化配置
    let cnf = config::Cnf::new("qmt.toml");
    if let Err(e) = cnf {
        error!("初始化配置失败：{}", e.to_string());
        return;
    }
    let cnf = cnf.unwrap();
    let m_path = cnf.get("file", "path");
    if let Err(e) = m_path {
        error!("读取[file]中的path错误：{}", e.to_string());
        return;
    }
    let m_path = m_path.unwrap();
    let zjzh = cnf.get("zh", "zjzh");
    if let Err(e) = zjzh {
        error!("读取[zh]中的zjzh错误：{}", e.to_string());
        return;
    }
    // 资金账号
    let zjzh = zjzh.unwrap();
    // 文件输出路径
    let out_path = cnf.get("out", "path");
    if let Err(e) = out_path {
        error!("读取[out]的path错误：{}", e.to_string());
        return;
    }
    let out_path = out_path.unwrap();
    // 委托文件
    let wt_file = cnf.get("out", "wt");
    if let Err(e) = wt_file {
        error!("读取[out]中的wt错误：{}", e.to_string());
        return;
    }
    let wt_file = format!("{}{}", out_path, wt_file.unwrap());
    // 持仓文件
    let cc_file = cnf.get("out", "cc");
    if let Err(e) = cc_file {
        error!("读取[out]中的cc错误：{}", e.to_string());
        return;
    }
    let cc_file = format!("{}{}", out_path, cc_file.unwrap());
    // 账户文件
    let zh_file = cnf.get("out", "zh");
    if let Err(e) = zh_file {
        error!("读取[out]中的zh错误：{}", e.to_string());
        return;
    }
    let zh_file = format!("{}{}", out_path, zh_file.unwrap());
    // 频率
    let freq: C_Result<String, std::io::Error> = cnf.get("freq", "fq");
    if let Err(e) = freq {
        error!("读取[freq]中的fq错误：{}", e.to_string());
        return;
    }
    let freq = freq.unwrap();
    let fq_vec: Vec<&str> = freq.split("/").collect();
    if fq_vec.len() != 2 {
        error!("配置[freq]中的fq错误");
        return;
    }
    let fq_num = fq_vec[0].parse::<usize>();
    let fq_sec = fq_vec[1].parse::<i32>();
    if fq_num.is_err() {
        error!("配置[freq]中的fq内容错误");
        return;
    }
    if fq_sec.is_err() {
        error!("配置[freq]中的fq内容错误");
        return;
    }
    let fq_num = fq_num.unwrap();
    let fq_sec = fq_sec.unwrap();
    if fq_num < 1 || fq_sec < 1 {
        error!("配置[freq]中的fq数值不能小于1");
        return;
    }
    info!("处理频率: {}秒{}笔", fq_sec, fq_num);

    let count = cnf.get("freq", "count");
    if let Err(e) = count {
        error!("读取[freq]中的count错误:{}", e.to_string());
        return;
    }
    let count = count.unwrap().parse::<usize>();
    if let Err(e) = count {
        error!("配置[freq]中的count错误:{}", e.to_string());
        return;
    }
    let count = count.unwrap();
    info!("每处理{}只股票后，休眠一会", count);
    // url
    let url: C_Result<String, std::io::Error> = cnf.get("server", "url");
    if let Err(e) = url {
        error!("读取[server]中的url错误:{}", e.to_string());
        return;
    }
    let url = url.unwrap();

    // 初始化加解密
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

    let mut f = File::open("yg_public.pem").expect("打开yg_public文件失败");
    let mut yg_public = String::new();
    f.read_to_string(&mut yg_public)
        .expect("获取yg_public内容失败");
    let pub_key: RsaPublicKey =
        RsaPublicKey::from_public_key_pem(&yg_public).expect("初始化公钥失败");

    let mut f = File::open("ygb_private.pem").expect("打开ygb_private文件失败");
    let mut ygb_priv = String::new();
    f.read_to_string(&mut ygb_priv)
        .expect("获取ygb_private内容失败");

    let priv_key = RsaPrivateKey::from_pkcs1_pem(&ygb_priv).expect("初始化私钥失败");

    let gbk_encoding: &Encoding =
        Encoding::for_label("GBK".as_bytes()).expect("初始化GBK解码器失败");

    let stock_vec: Vec<StockOp> = vec![];
    let cc_vec: Vec<StockCC> = vec![];
    let zh_info = ZhInfo {
        stock_capitalization: 0.0,
        available_balance: 0.0,
        total_asset: 0.0,
        freeze_balance: 0.0,
    };

    let arc_lock: Arc<Mutex<(Vec<StockOp>, usize)>> = Arc::new(Mutex::new((stock_vec, 0)));
    let arc_cc_lock: Arc<Mutex<Vec<StockCC>>> = Arc::new(Mutex::new(cc_vec));
    let arc_zh_lock: Arc<Mutex<ZhInfo>> = Arc::new(Mutex::new(zh_info));

    let arc_cc_thd = arc_cc_lock.clone();
    let arc_loc_thd = arc_lock.clone();
    let arc_zh_thd = arc_zh_lock.clone();
    let m_path_thd = m_path.clone();
    let wt_file_thd = wt_file.clone();
    let zjzh_thd = zjzh.clone();
    let pub_key_thd = pub_key.clone();
    let url_thd = url.clone();

    let _thd = thread::spawn(move || {
        m_file_run(
            arc_loc_thd,
            arc_cc_thd,
            arc_zh_thd,
            fq_num,
            fq_sec,
            &m_path_thd,
            &wt_file_thd,
            &zjzh_thd,
            pub_key_thd,
            &url_thd,
            count,
        );
    });

    // 网络
    let http_client = reqwest::blocking::Client::builder()
        .build()
        .expect("初始化http库失败");

    let mut cc_sec = 0;
    let mut get_sec = 0;
    loop {
        get_cc_data(arc_cc_lock.clone(), &wt_file, &cc_file, gbk_encoding);
        get_zh_data(arc_zh_lock.clone(), &zh_file, gbk_encoding);
        if cc_sec >= 15 {
            let cc_ret = send_cc(
                &pub_key,
                &mut rng,
                &http_client,
                &url,
                arc_cc_lock.clone(),
                arc_zh_lock.clone(),
            );
            if let Err(e) = cc_ret {
                error!("发送持仓数据失败:{}", e.to_string());
            }
            cc_sec = 0;
        }
        if get_sec >= 2 {
            let get_ret = get_stock_list(
                &pub_key,
                &priv_key,
                &http_client,
                &mut rng,
                arc_lock.clone(),
                &url,
            );
            if let Err(e) = get_ret {
                error!("获取股票列表失败:{}", e.to_string());
            }
            get_sec = 0;
        }
        sleep(Duration::from_secs(1));
        cc_sec += 1;
        get_sec += 1;
    }

    //thd.join().unwrap();
}

// 发送持仓数据
fn send_cc<R>(
    pub_key: &RsaPublicKey,
    rng: &mut R,
    http_client: &reqwest::blocking::Client,
    url: &String,
    cc_vec_arc: Arc<Mutex<Vec<StockCC>>>,
    zh_info_arc: Arc<Mutex<ZhInfo>>,
) -> C_Result<(), std::io::Error>
where
    R: CryptoRngCore,
{
    let mut stock_list = String::from("[");
    {
        let cc_vec = cc_vec_arc.lock();
        if let Err(e) = cc_vec {
            return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
        }
        let cc_vec = cc_vec.unwrap();

        for stock in cc_vec.iter() {
            let stock_json = format!(
            "{{\"stock_id\":\"{}\",\"stock_name\":\"{}\",\"amount\":\"{}\",\"holding_cost\":\"{}\",\"status\":{}}}",
            stock.stock_id, stock.stock_name, stock.amount, stock.holding_cost,stock.status
        );
            stock_list = stock_list + stock_json.as_str() + ",";
        }
    }

    let len = stock_list.len();
    if len > 1 {
        stock_list.truncate(len - 1);
    }
    stock_list += "]";

    //debug!("持仓列表:{}", stock_list);

    // 账户信息
    let (stock_capitalization, available_balance, total_asset, freeze_balance) = {
        let zh_info = zh_info_arc.lock();
        if let Err(e) = zh_info {
            return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
        }
        let zh_info = zh_info.unwrap();
        (
            zh_info.stock_capitalization,
            zh_info.available_balance,
            zh_info.total_asset,
            zh_info.freeze_balance,
        )
    };

    // request data
    let req_data = format!("{{\"c\":\"stock_account\",\"f\":\"update_account_info\",\"stock_capitalization\":{},\"available_balance\":{},\"total_asset\":{},\"freeze_balance\":{},\"holding_stock_list\":{}}}",stock_capitalization,available_balance,total_asset,freeze_balance,stock_list);
    let b64 = split_str_encrypt(&req_data, 117, pub_key, rng)?;

    // md5(account_name + request_data + ts + md5秘钥 )
    let ts = Local::now().timestamp();
    let hex_string: String = get_md5(ts, &b64);
    //let verify = String::from_utf8_lossy(&digest);
    //let verify_str = match verify {
    //    Cow::Borrowed(str) => str.to_string(),
    //    Cow::Owned(s) => s,
    //};
    //if let Err(e) = verify {
    //    println!("{}", e.to_string());
    //    return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
    //}

    let ret_js = format!(
        "{{\"account_name\":\"yg\",\"request_data\":\"{}\",\"ts\":{},\"verify\":\"{}\"}}",
        b64, ts, hex_string
    );

    let http_ret = http_client
        .post(url)
        .body(ret_js)
        .timeout(Duration::from_secs(10))
        .header("Content-Type", "application/json")
        .send();

    if let Err(e) = http_ret {
        error!("发送持仓数据错误: {}", e.to_string());
    }

    Ok(())
}

// 获取帐号数据
fn get_zh_data(zh_arc: Arc<Mutex<ZhInfo>>, zh_file: &str, gbk_encoding: &'static Encoding) {
    let ss = get_csv(zh_file, gbk_encoding);
    if let Err(e) = ss {
        error!("获取帐号数据错误:{}", e.to_string());
        return;
    }
    let ss = ss.unwrap();

    let mut rdr = csv::Reader::from_reader(ss.as_bytes());
    let mut zh_rec: StringRecord = StringRecord::new();
    let zh_ret = rdr.read_record(&mut zh_rec);
    if let Err(e) = zh_ret {
        error!("读取帐号数据错误:{}", e.to_string());
        return;
    }
    let stock_capitalization = zh_rec.get(10).unwrap_or("0");
    let available_balance = zh_rec.get(7).unwrap_or("0");
    let total_asset = zh_rec.get(6).unwrap_or("0");
    let freeze_balance = zh_rec.get(5).unwrap_or("0");

    let zh_info = zh_arc.lock();
    if let Err(e) = zh_info {
        error!("获取帐号数据的锁失败:{}", e.to_string());
        return;
    }
    let mut zh_info = zh_info.unwrap();
    zh_info.stock_capitalization = stock_capitalization.parse::<f64>().unwrap_or(0.0);
    zh_info.available_balance = available_balance.parse::<f64>().unwrap_or(0.0);
    zh_info.total_asset = total_asset.parse::<f64>().unwrap_or(0.0);
    zh_info.freeze_balance = freeze_balance.parse::<f64>().unwrap_or(0.0);
}

// 获取持仓数据
fn get_cc_data(
    cc_vec_arc: Arc<Mutex<Vec<StockCC>>>,
    wt_file: &str,
    cc_file: &str,
    gbk_encoding: &'static Encoding,
) {
    let mut tmp_vec: Vec<StockCC> = vec![];
    // 委托
    let wt = get_wt_list(wt_file, gbk_encoding);
    if let Err(e) = wt {
        error!("获取持仓委托数据错误:{}", e.to_string());
        return;
    }
    let wt = wt.unwrap();
    for w in wt {
        if w.status == "已撤" || w.status == "已成" || w.status == "未报" || w.status == "废单"
        {
            continue;
        }

        tmp_vec.push(StockCC {
            stock_id: w.stock_id,
            stock_name: w.stock_name,
            amount: w.count,
            holding_cost: "0".to_string(),
            status: "2".to_string(),
            remain: 0,
            flag: 0,
        });
    }
    // 持仓
    let ss = get_csv(cc_file, gbk_encoding);
    if let Err(e) = ss {
        error!("读取持仓文件错误:{}", e.to_string());
        return;
    }
    let ss = ss.unwrap();

    let mut rdr = csv::Reader::from_reader(ss.as_bytes());
    for r in rdr.records() {
        if let Ok(rec) = r {
            let stock_id = rec.get(7).unwrap_or("").to_string();
            let stock_name = rec.get(8).unwrap_or("").to_string();
            let amount = rec.get(9).unwrap_or("").to_string();
            let holding_cost = rec.get(10).unwrap_or("").to_string();
            let remain = rec.get(15).unwrap_or("0").parse::<usize>().unwrap_or(0);

            tmp_vec.push(StockCC {
                stock_id,
                stock_name,
                amount,
                holding_cost,
                status: "1".to_string(),
                remain,
                flag: 1,
            });
        }
    }
    let lvl = log::max_level();
    if lvl == LevelFilter::Debug {
        let mut p_str = String::new();
        for t in &tmp_vec {
            p_str += &format!(
                "({},{},{},{},{},{})\n",
                t.stock_id, t.stock_name, t.amount, t.remain, t.holding_cost, t.status
            );
        }
        if p_str.len() > 1 {
            p_str.truncate(p_str.len() - 1);
        }
        debug!("持仓数量:{}\n{}", tmp_vec.len(), p_str);
    }

    let cc_vec = cc_vec_arc.lock();
    if let Err(e) = cc_vec {
        error!("获取锁失败:{}", e.to_string());
        return;
    }
    let mut cc_vec = cc_vec.unwrap();
    cc_vec.clear();
    cc_vec.extend(tmp_vec);
}

// 获取股票列表
fn get_stock_list<R: CryptoRngCore>(
    pub_key: &RsaPublicKey,
    priv_key: &RsaPrivateKey,
    http_client: &reqwest::blocking::Client,
    rng: &mut R,
    arc_lock: Arc<Mutex<(Vec<StockOp>, usize)>>,
    url: &String,
) -> C_Result<(), std::io::Error> {
    let req_data = "{\"c\":\"stock_account\",\"f\":\"get_oper_list\"}";
    let b64 = split_str_encrypt(&req_data.to_string(), 117, pub_key, rng)?;

    // md5(account_name + request_data + ts + md5秘钥 )
    let ts = Local::now().timestamp();
    let hex_string: String = get_md5(ts, &b64);

    let ret_js = format!(
        "{{\"account_name\":\"yg\",\"request_data\":\"{}\",\"ts\":{},\"verify\":\"{}\"}}",
        b64, ts, hex_string
    );

    let http_ret = http_client
        .post(url)
        .body(ret_js)
        .timeout(Duration::from_secs(10))
        .header("Content-Type", "application/json")
        .send();

    if let Err(e) = http_ret {
        return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
    }

    let resp = http_ret.unwrap();
    if resp.status() != 200 {
        let err_str = format!("get_stock_list返回码:{}", resp.status());
        return Err(std::io::Error::new(ErrorKind::Other, err_str));
    }

    let resp_text = resp.text();
    if let Err(e) = resp_text {
        return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
    }

    let data = get_resp_data(priv_key, &resp_text.unwrap())?;

    // 解析股票列表
    let v: Value = serde_json::from_str(&data)?;

    let arr = v["oper_stock_list"].as_array();
    if let None = arr {
        return Err(std::io::Error::new(ErrorKind::Other, "oper_stock_list为空"));
    }
    let arr = arr.unwrap();

    let mut stock_vec: Vec<StockOp> = vec![];
    for a in arr {
        let id = a["id"].as_str().unwrap_or("").to_string();
        let stock_id = a["stock_id"].as_str().unwrap_or("").to_string();
        let oper_type = if a["oper_type"].is_string() {
            a["oper_type"].as_str().unwrap_or("").to_string() // 操作类型，1是买，2是卖，3是撤单买，4是撤单卖
        } else if a["oper_type"].is_i64() {
            a["oper_type"].as_i64().unwrap_or(0).to_string()
        } else {
            String::from("")
        };
        let target_price_ori = a["target_price"].as_str().unwrap_or("").to_string();
        let target_price = (target_price_ori.parse::<f32>().unwrap_or(0.0) * 1000.0) as usize;
        let target_amount = a["target_amount"]
            .as_str()
            .unwrap_or("")
            .to_string()
            .parse::<usize>()
            .unwrap_or(0);
        let stock_name = a["stock_name"].as_str().unwrap_or("").to_string();
        let comments = a["comments"].as_str().unwrap_or("").to_string();

        stock_vec.push(StockOp {
            stock_id,
            oper_type,
            target_price,
            target_amount,
            stock_name,
            target_price_ori,
            id,
            comments,
        });
    }

    let lvl: LevelFilter = log::max_level();
    if lvl == LevelFilter::Debug {
        let mut p_str = String::new();
        for ii in stock_vec.iter() {
            p_str += &format!(
                "({},{},{},{},{},{},{})\n",
                ii.stock_id,
                ii.oper_type,
                ii.target_price,
                ii.target_amount,
                ii.stock_name,
                ii.target_price_ori,
                ii.id
            );
        }
        if p_str.len() > 1 {
            p_str.truncate(p_str.len() - 1);
        }
        debug!("返回列表数量:{}\n{}", stock_vec.len(), p_str);
    }

    let lk = arc_lock.lock();
    if let Err(e) = lk {
        error!("获取股票列表时,lock失败:{}", e.to_string());
    } else {
        //lk.unwrap().extend(stock_vec);
        let mut lk_obj = lk.unwrap();
        lk_obj.1 = stock_vec.len();
        let lk2 = &mut lk_obj.0;

        for new_item in stock_vec {
            let item = lk2.iter().find(|&x| x.id == new_item.id);
            if let None = item {
                lk2.push(new_item);
            }
        }

        if lvl == LevelFilter::Debug {
            let mut p_str = String::new();
            for ii in lk2.iter() {
                p_str += &format!(
                    "({},{},{},{},{},{},{})\n",
                    ii.stock_id,
                    ii.oper_type,
                    ii.target_price,
                    ii.target_amount,
                    ii.stock_name,
                    ii.target_price_ori,
                    ii.id
                );
            }
            if p_str.len() > 1 {
                p_str.truncate(p_str.len() - 1);
            }
            debug!("当前列表数量:{}\n{}", lk2.len(), p_str);
        }
    }
    //let oper_notify = make_m_file(stock_vec, m_path, wt_file, gbk_encoding, zjzh)?;

    Ok(())
}

fn get_md5(ts: i64, b64: &String) -> String {
    let pre_md5 = format!("yg{}{}{}", b64, ts, "Kmdje29TYbvdj3=kM<deh");
    let digest: [u8; 16] = md5::compute(pre_md5.as_bytes()).0;
    digest.iter().map(|byte| format!("{:02x}", byte)).collect()
}

// 按长度分割字符串,并加密,返回base64
fn split_str_encrypt<R: CryptoRngCore>(
    s: &String,
    len: usize,
    pub_key: &RsaPublicKey,
    rng: &mut R,
) -> C_Result<String, std::io::Error> {
    let s_bytes = s.as_bytes();
    let slen = s_bytes.len();
    let mut ret_str = Vec::<u8>::new();
    let mut l: i32 = slen as i32;
    let mut start = 0;
    let mut end: usize;
    while l > 0 {
        end = start + len;
        if end > slen {
            end = slen;
        }
        let s1 = &s_bytes[start..end];
        l = l - (len as i32);
        start += len;
        // 加密
        let req_crypt = pub_key.encrypt(rng, Pkcs1v15Encrypt, s1);
        if let Err(e) = req_crypt {
            return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
        }
        let s = req_crypt.unwrap();
        ret_str.extend(s);
    }

    let b64 = general_purpose::STANDARD_NO_PAD.encode(ret_str);

    Ok(b64)
}

// base64字符串切割解密
fn split_str_decrypt(s: &str, priv_key: &RsaPrivateKey) -> C_Result<String, std::io::Error> {
    let dcode = general_purpose::STANDARD.decode(s);
    if let Err(e) = dcode {
        return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
    }
    let mut ret_vec: Vec<u8> = Vec::new();
    let vec = dcode.unwrap();
    let slen = vec.len();
    let mut l: i32 = slen as i32;
    let mut start = 0;
    let mut end: usize;

    while l > 0 {
        end = start + 128;
        if end > slen {
            end = slen;
        }
        let s1 = &vec[start..end];
        let data = priv_key.decrypt(Pkcs1v15Encrypt, &s1);
        if let Err(e) = data {
            return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
        }
        ret_vec.extend(data.unwrap());
        l = l - 128;
        start += 128;
    }

    let ss = String::from_utf8(ret_vec);
    if let Err(e) = ss {
        return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
    }

    Ok(ss.unwrap())
}

fn get_csv(file: &str, gbk_encoding: &'static Encoding) -> C_Result<String, std::io::Error> {
    let mut f = File::open(file)?;

    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;

    let c = gbk_encoding.decode(&buf).0;

    let ss = match c {
        Cow::Borrowed(s) => s.to_string(),
        Cow::Owned(s) => s,
    };
    Ok(ss)
}

fn get_resp_data(priv_key: &RsaPrivateKey, resp_text: &str) -> C_Result<String, std::io::Error> {
    let v: Value = serde_json::from_str(resp_text)?;

    let code = &v["response_code"].as_i64();
    if let None = code {
        return Err(std::io::Error::new(ErrorKind::Other, "response_code不为1"));
    }

    let data = &v["response_data"].as_str();
    if let None = code {
        return Err(std::io::Error::new(ErrorKind::Other, "response_data为空"));
    }

    let s = split_str_decrypt(data.unwrap(), priv_key)?;
    Ok(s)
}

// 获取委托列表
fn get_wt_list(
    wt_file: &str,
    gbk_encoding: &'static Encoding,
) -> C_Result<Vec<WtRecord>, std::io::Error> {
    let ss = get_csv(wt_file, gbk_encoding)?;
    let mut wt_vec: Vec<WtRecord> = vec![];
    let mut rdr = csv::Reader::from_reader(ss.as_bytes());
    for r in rdr.records() {
        if let Ok(rec) = r {
            let stock_id = rec.get(11).unwrap_or("").to_string();
            let stock_name = rec.get(12).unwrap_or("").to_string();
            let price = rec.get(13).unwrap_or("").parse::<f32>().unwrap_or(0.0);
            let price = (price * 1000.0) as i32;
            let count = rec.get(14).unwrap_or("").to_string();
            //let time = rec.get(22).unwrap_or("").to_string();
            let flag = rec.get(25).unwrap_or("").to_string();
            let status = rec.get(16).unwrap_or("").to_string();
            let order_num = rec.get(29).unwrap_or("").to_string();
            let comments = rec.get(9).unwrap_or("").to_string();

            let wt = WtRecord {
                stock_id,
                stock_name,
                _price: price,
                count,
                //time,
                flag,
                status,
                order_num,
                comments,
            };
            wt_vec.push(wt);
        }
    }

    Ok(wt_vec)
}

// 创建文件单
fn make_m_file(
    stock_vec: Vec<StockOp>,
    m_path: &str,
    wt_file: &str,
    gbk_encoding: &'static Encoding,
    zjzh: &str,
    cc_vec_arc: &Arc<Mutex<Vec<StockCC>>>,
    zh_info_arc: &Arc<Mutex<ZhInfo>>,
) -> C_Result<Vec<(String, String, String)>, std::io::Error> {
    let file_path = PathBuf::from(m_path);
    let mut file = File::create(&file_path)?;

    let wt_vec = get_wt_list(wt_file, gbk_encoding)?;

    let mut oper_notify: Vec<(String, String, String)> = vec![];
    //let mut ret_vec: Vec<(String, String, i32, String, String, String)> = vec![];

    let mut content = String::new();
    for stock_op in stock_vec {
        if stock_op.stock_id == ""
            || stock_op.oper_type == ""
            || stock_op.target_price == 0
            || stock_op.target_amount == 0
        {
            info!("有空数据");
            continue;
        }

        if stock_op.oper_type == "1" {
            let fditer = wt_vec
                .iter()
                .filter(|&x| x.stock_id == stock_op.stock_id && x.flag == "限价买入");
            let mut buy = true;
            let mut c_buy = false;
            let mut f_num = 0;
            for wt in fditer {
                if wt.status == "已撤" {
                    continue;
                }
                if wt.status == "废单" {
                    // 如果出现3次价格相同的废单，则不交易
                    //if wt.price == stock_op.target_price {
                    //    f_num += 1;
                    //}
                    if wt.comments == stock_op.comments {
                        f_num += 1;
                    }
                    continue;
                }
                if wt.comments == stock_op.comments {
                    // 不重复买
                    buy = false;
                } else if wt.status == "已报" {
                    c_buy = true;
                    content += &format!("cancel_order_number {} {}\r\n", zjzh, wt.order_num);
                    info!("撤原有买单[{}],订单:{}", stock_op.stock_id, wt.order_num);
                }
            }
            if buy && f_num < 3 {
                // 判断余额
                let ava = get_available_balance(zh_info_arc);
                let cct = (stock_op.target_price * stock_op.target_amount) as f64;

                if cct > ava * 1000.0 {
                    info!(
                        "余额不足买入:[{}],{},{}, 余额:{}",
                        stock_op.stock_id, stock_op.target_price_ori, stock_op.target_amount, ava
                    );
                    continue;
                }

                content += &format!(
                    "23,0,{},{},{}\r\norderparam=<tag>note={}</tag>\r\n",
                    stock_op.target_price_ori,
                    stock_op.stock_id,
                    stock_op.target_amount,
                    stock_op.comments
                );
                info!(
                    "买入[{}],{}股,价格:{},备注:{}",
                    stock_op.stock_id,
                    stock_op.target_amount,
                    stock_op.target_price_ori,
                    stock_op.comments
                );
                oper_notify.push((
                    stock_op.stock_id.clone(),
                    stock_op.stock_name.clone(),
                    stock_op.oper_type.clone(),
                ));
            } else if c_buy {
                info!("下一次再买入[{}],不执行", stock_op.stock_id);
                /*ret_vec.push((
                    stock_id,
                    oper_type,
                    target_price,
                    target_amount,
                    stock_name,
                    target_price_ori,
                ));*/
            } else {
                info!(
                    "重复买入[{}],备注:{},不执行",
                    stock_op.stock_id, stock_op.comments
                );
            }
        } else if stock_op.oper_type == "2" {
            let fditer = wt_vec
                .iter()
                .filter(|&x| x.stock_id == stock_op.stock_id && x.flag == "限价卖出");
            let mut sell = true;
            let mut c_sell = false;
            let mut f_num = 0;
            for wt in fditer {
                if wt.status == "已撤" {
                    continue;
                }
                if wt.status == "废单" {
                    // 如果出现3次价格相同的废单，则不交易
                    if wt.comments == stock_op.comments {
                        f_num += 1;
                    }
                    continue;
                }
                //if wt.price == stock_op.target_price && wt.count == stock_op.target_amount {
                if wt.comments == stock_op.comments {
                    // 不重复卖
                    sell = false;
                } else if wt.status == "已报" {
                    c_sell = true;
                    content += &format!("cancel_order_number {} {}\r\n", zjzh, wt.order_num);
                    info!("撤原有卖单[{}],订单:{}", stock_op.stock_id, wt.order_num);
                }
            }

            if sell && f_num < 3 {
                let remain = get_stock_remain(&stock_op.stock_id, &cc_vec_arc);
                let mut num = stock_op.target_amount;
                if let Some(rr) = remain {
                    if num > rr {
                        num = rr;
                    }
                    if num > 0 {
                        content += &format!(
                            "24,0,{},{},{}\r\norderparam=<tag>note={}</tag>\r\n",
                            stock_op.target_price_ori, stock_op.stock_id, num, stock_op.comments
                        );
                        info!(
                            "卖出[{}],{}股,价格:{},数量:{},备注:{}",
                            stock_op.stock_id,
                            stock_op.target_amount,
                            stock_op.target_price_ori,
                            num,
                            stock_op.comments
                        );
                        oper_notify.push((
                            stock_op.stock_id.clone(),
                            stock_op.stock_name.clone(),
                            stock_op.oper_type.clone(),
                        ));
                    }
                } else {
                    info!("查找股票[{}]的可用股数为None", stock_op.stock_id);
                }
            } else if c_sell {
                info!("下一次再卖出[{}],不执行", stock_op.stock_id);
                /*ret_vec.push((
                    stock_id,
                    oper_type,
                    target_price,
                    target_amount,
                    stock_name,
                    target_price_ori,
                ));*/
            } else {
                info!(
                    "重复卖出[{}],备注:{},不执行",
                    stock_op.stock_id, stock_op.comments
                );
            }
        } else if stock_op.oper_type == "3" {
            // 撤单买 cancel_order_number 资金账号 订单编号
            info!("撤单买:[{}]", stock_op.stock_id);
            for wt in wt_vec.iter() {
                if wt.stock_id == stock_op.stock_id
                    && wt.flag == "限价买入"
                    && wt.status != "已撤"
                    && wt.status != "废单"
                {
                    content += &format!("cancel_order_number {} {}\r\n", zjzh, wt.order_num);
                    oper_notify.push((
                        stock_op.stock_id.clone(),
                        stock_op.stock_name.clone(),
                        stock_op.oper_type.clone(),
                    ));
                    info!("撤单买[{}],订单:{}", stock_op.stock_id, wt.order_num);
                }
            }
        } else if stock_op.oper_type == "4" {
            // 撤单卖
            info!("撤单卖:[{}]", stock_op.stock_id);
            for wt in wt_vec.iter() {
                if wt.stock_id == stock_op.stock_id
                    && wt.flag == "限价卖出"
                    && wt.status != "已撤"
                    && wt.status != "废单"
                {
                    content += &format!("cancel_order_number {} {}\r\n", zjzh, wt.order_num);
                    oper_notify.push((
                        stock_op.stock_id.clone(),
                        stock_op.stock_name.clone(),
                        stock_op.oper_type.clone(),
                    ));
                    info!("撤单卖[{}],订单:{}", stock_op.stock_id, wt.order_num);
                }
            }
        } else {
            error!("错误的操作类型:{}", stock_op.oper_type);
        }
    }
    file.write(content.as_bytes())?;

    Ok(oper_notify)
}

// 发送操作结果
fn send_oper_notify<R: CryptoRngCore>(
    oper_notify: Vec<(String, String, String)>,
    pub_key: &RsaPublicKey,
    rng: &mut R,
    http_client: &reqwest::blocking::Client,
    url: &String,
) -> C_Result<(), std::io::Error> {
    if oper_notify.len() == 0 {
        return Ok(());
    }
    let mut list = String::from("[");
    for (stock_id, stock_name, oper_type) in oper_notify {
        let s = format!(
            "{{\"stock_id\":\"{}\",\"stock_name\":\"{}\",\"oper_type\":\"{}\"}},",
            stock_id, stock_name, oper_type
        );

        list += &s;
    }
    let len = list.len();
    if len > 1 {
        list.truncate(len - 1);
    }
    list += "]";
    // request data
    let req_data = format!(
        "{{\"c\":\"stock_account\",\"f\":\"oper_notify\",\"oper_stock_result_list\":{}}}",
        list
    );
    //println!("{:?}", req_data);
    let b64 = split_str_encrypt(&req_data, 117, pub_key, rng)?;

    let ts = Local::now().timestamp();
    let hex_string: String = get_md5(ts, &b64);

    let ret_js = format!(
        "{{\"account_name\":\"yg\",\"request_data\":\"{}\",\"ts\":{},\"verify\":\"{}\"}}",
        b64, ts, hex_string
    );

    let http_ret = http_client
        .post(url)
        .body(ret_js)
        .timeout(Duration::from_secs(10))
        .header("Content-Type", "application/json")
        .send();

    if let Err(e) = http_ret {
        error!("发送操作结果错误: {}", e.to_string());
    }

    Ok(())
}

// 异步处理文件单
fn m_file_run(
    arc_lock: Arc<Mutex<(Vec<StockOp>, usize)>>,
    cc_vec_arc: Arc<Mutex<Vec<StockCC>>>,
    zh_info_arc: Arc<Mutex<ZhInfo>>,
    fq_num: usize,
    fq_sec: i32,
    m_path: &str,
    wt_file: &str,
    zjzh: &str,
    pub_key: RsaPublicKey,
    url: &String,
    count: usize,
) {
    let gbk_encoding: &Encoding =
        Encoding::for_label("GBK".as_bytes()).expect("文件单线程初始化GBK解码器失败");
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

    let http_client = reqwest::blocking::Client::builder()
        .build()
        .expect("文件单线程初始化http客户端失败");

    info!("处理文件单的线程启动");

    // 每1秒循环一次，fq_sec秒操作一次
    let mut sec = 0;
    let mut rm_num = fq_num;
    let mut rm_all: usize = 0;
    // let mut stock_num: usize = 0;
    loop {
        let mut oper_num: usize = 0;
        if sec >= fq_sec {
            let rm_items = {
                let lk = arc_lock.lock();
                if let Err(e) = lk {
                    error!("arc_lock执行lock错误:{}", e.to_string());
                    None
                } else {
                    let mut lk_obj = lk.unwrap();
                    //stock_num = lk_obj.1;
                    let lk = &mut lk_obj.0;
                    // 获取几笔
                    //let mut num: usize = rm_num as usize;
                    if rm_num > lk.len() {
                        rm_num = lk.len();
                    }
                    let rm_items: Vec<StockOp> = lk.drain(0..rm_num).collect();
                    //debug!("取出后列表数量:{},{:?}", lk.len(), lk);
                    Some(rm_items)
                }
            };
            if let Some(items) = rm_items {
                // 生成文件单
                if items.len() > 0 {
                    info!("取出{}条数据,生成文件单", items.len());
                    rm_all += items.len();
                    let make_ret = make_m_file(
                        items,
                        m_path,
                        wt_file,
                        gbk_encoding,
                        zjzh,
                        &cc_vec_arc,
                        &zh_info_arc,
                    );
                    // 发送操作结果
                    if let Ok(oper_notify) = make_ret {
                        // 回补
                        /*if ret_vec.len() > 0 {
                            let lk = arc_lock.lock();
                            if let Err(e) = lk {
                                error!("回补数据时获取lock错误:{}", e.to_string());
                            } else {
                                let mut lk = lk.unwrap();
                                for rr in ret_vec.iter().rev() {
                                    lk.insert(0, rr.clone());
                                }
                                info!("回补后列表:{:?}", lk);
                            }
                        }*/

                        oper_num = oper_notify.len();

                        let notify_ret =
                            send_oper_notify(oper_notify, &pub_key, &mut rng, &http_client, url);
                        if let Err(e) = notify_ret {
                            error!("发送操作结果失败: {}", e.to_string());
                        }
                    } else {
                        let e = make_ret.err().unwrap();
                        error!("生成文件单错误: {}", e.to_string());
                    }
                }
            }
            if oper_num < rm_num {
                // 所有股票已经遍历过一遍
                if rm_all >= count {
                    rm_num = fq_num;
                    sec = 0;
                    rm_all = 0;
                } else {
                    rm_num = rm_num - oper_num;
                    sleep(Duration::from_millis(20));
                    continue;
                }
            } else {
                rm_num = fq_num;
                sec = 0;
            }
        }
        sleep(Duration::from_millis(1000));
        sec += 1;
    }
}

fn get_stock_remain(stock_id: &String, cc_vec_arc: &Arc<Mutex<Vec<StockCC>>>) -> Option<usize> {
    let cc_vec = cc_vec_arc.lock();
    if let Err(e) = cc_vec {
        error!("获取[{}]的可用股数失败:{}", stock_id, e.to_string());
        return None;
    }
    let cc_vec = cc_vec.unwrap();
    let item = cc_vec
        .iter()
        .find(|&x| &x.stock_id == stock_id && x.flag == 1);
    if let Some(s) = item {
        Some(s.remain)
    } else {
        None
    }
}

fn get_available_balance(zh_info_arc: &Arc<Mutex<ZhInfo>>) -> f64 {
    let zh_info = zh_info_arc.lock();
    if let Err(e) = zh_info {
        error!("获取帐号数据的锁失败:{}", e.to_string());
        return 0.0;
    }
    zh_info.unwrap().available_balance
}

// 每次一天
fn get_min_klines(
    symbol: &str,
    start_time: u64,
    base_asset: &str,
    quote_asset: &str,
) -> std::result::Result<(), String> {
    let prx = reqwest::Proxy::https("http://127.0.0.1:7890").unwrap();

    let cl2 = reqwest::blocking::Client::builder()
        .proxy(prx)
        .build()
        .unwrap();

    let mut start = start_time;
    let mut daystr = String::from("[");

    let mut end: u64 = start_time;
    for _i in 0..15 {
        end = start + 6060000; // 101分钟
        if end > start_time + 86460000 {
            end = start_time + 86460000; // 第二天0点
        }
        let url = format!(
            "https://www.www.com/w/v5/w/w?instId={}&bar=1m&after={}&before={}",
            symbol, end, start
        );

        let re = cl2.get(url).timeout(Duration::from_secs(10)).send();
        if let Err(e) = re {
            return Err(e.to_string());
        }
        let rr = re.unwrap();
        if rr.status() != 200 {
            error!("返回错误码:{}", rr.status());
            return Err(rr.status().to_string());
        }

        let content = rr.text();
        if let Err(e) = content {
            return Err(e.to_string());
        }
        let content = content.unwrap();

        //println!("{}, {},{}", start, end, content);

        start = end - 60000; // -1分钟

        // 解析json
        let jn: Result<Value> = serde_json::from_str(&content);
        if let Ok(v) = jn {
            let mp = v.as_object();
            if let Some(j2m) = mp {
                let data = j2m.get("data");
                if let Some(vec) = data {
                    let d2v = vec.as_array();
                    if let Some(vv) = d2v {
                        let mut st = String::from("");

                        for k in vv.iter().rev() {
                            let omk = k.as_array();
                            if let Some(mk) = omk {
                                st = st + &vec2string(mk) + ",";
                            } else {
                                return Err("Value转Vec错误".to_string());
                            }
                        }
                        daystr += &st;
                        sleep(Duration::from_millis(100));
                        continue;
                    }
                }
            }
        }
        return Err("解析抓取到的json错误".to_string());
    }
    let len = daystr.len();
    if len > 1 {
        daystr.truncate(len - 1);
    }
    daystr += "]";
    //println!("{}", daystr);

    let cl3 = reqwest::blocking::Client::builder().build().unwrap();

    let upcontent = format!(
        "{{\"symbol\":\"{}\",\"base_asset\":\"{}\",\"quote_asset\":\"{}\",\"k\":{},\"endTime\":{}}}",
        symbol, base_asset, quote_asset, daystr,end - 60000
    );

    if daystr == "[]" {
        error!("获取到的内容：{}", upcontent);
    }

    let resp = cl3
        .post("http://127.0.0.1:8008/post_okx_k1m.php")
        .body(upcontent)
        .timeout(Duration::from_secs(40))
        .header("Content-Type", "application/json")
        .send();

    if let Err(e) = resp {
        return Err(e.to_string());
    }

    let sts = resp.unwrap().status();
    if sts != 200 {
        return Err(format!("{} 上传服务器失败: {}", symbol, sts));
    }

    Ok(())
}

fn get_day_klines(
    symbol: &str,
    start_time: u64,
    end_time: u64,
    base_asset: &str,
    quote_asset: &str,
) -> std::result::Result<(), String> {
    let prx = reqwest::Proxy::https("http://127.0.0.1:7890").unwrap();

    let url = format!(
        "https://www.www.com/w/v5/w/w?instId={}&before={}&after={}&bar=1Dutc",
        symbol, start_time, end_time
    );

    //error!("url: {}", url);

    let cl2 = reqwest::blocking::Client::builder()
        .proxy(prx)
        .build()
        .unwrap();

    let cl3 = reqwest::blocking::Client::builder().build().unwrap();

    let re = cl2.get(url).timeout(Duration::from_secs(15)).send();
    if let Err(e) = re {
        return Err(e.to_string());
    }

    let rr = re.unwrap();
    if rr.status() != 200 {
        error!("返回错误码{}", rr.status());
        return Err(rr.status().to_string());
    }
    let content = rr.text().unwrap();

    /*let jn: Result<Value> = serde_json::from_str(&content);
    if jn.is_err() {
        error!("解析返回k线的json错误: {}", content);
        return Err(content);
    }

    let v = jn.unwrap();
    let m = v.as_object().unwrap();
    let content = if let Some(arr) = m.get("data") {
        let a = arr.as_array().unwrap();

        a.as_str().unwrap()
    } else {
        "[]"
    };*/

    //if content == "[]" {
    //    return Ok(());
    //}

    let upcontent = format!(
        "{{\"symbol\":\"{}\",\"base_asset\":\"{}\",\"quote_asset\":\"{}\",\"k\":{},\"endTime\":{}}}",
        symbol, base_asset, quote_asset, content, end_time
    );

    if content == "[]" {
        error!("获取到的内容：{}", upcontent);
    }

    let resp = cl3
        .post("http://127.0.0.1:8008/post_okx_k1d.php")
        .body(upcontent)
        .timeout(Duration::from_secs(30))
        .header("Content-Type", "application/json")
        .send();

    if let Err(e) = resp {
        return Err(e.to_string());
    }

    let sts = resp.unwrap().status();
    if sts != 200 {
        return Err(format!("{} 上传服务器失败: {}", symbol, sts));
    }

    Ok(())
}

fn vec2string(vec: &Vec<Value>) -> String {
    let mut ret = "[".to_string();
    for i in vec {
        ret = ret + i.as_str().unwrap() + ",";
    }
    let len = ret.len();
    if len > 1 {
        ret.truncate(len - 1);
    }
    ret + "]"
}
