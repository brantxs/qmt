use std::fs::File;
use std::io::Error;
use std::io::ErrorKind;
use std::io::Read;
use toml::map::Map;
use toml::Value;

pub struct Cnf {
    pub data: Map<String, Value>,
}

impl Cnf {
    pub fn new(file: &str) -> Result<Cnf, Error> {
        let mut fs = File::open(file)?;
        let mut buf: String = String::new();
        fs.read_to_string(&mut buf)?;
        let ml: Result<Value, toml::de::Error> = toml::from_str(&buf);
        if let Err(e) = ml {
            return Err(Error::new(ErrorKind::Other, e.to_string()));
        }
        let ml = ml.unwrap();
        let mp = match ml {
            Value::Table(t) => t,
            _ => {
                return Err(Error::new(ErrorKind::Other, "Value转Map失败"));
            }
        };

        Ok(Cnf { data: mp })
    }

    pub fn get(&self, parent: &str, child: &str) -> Result<String, Error> {
        let pr = self.data.get(parent);
        if let None = pr {
            return Err(Error::new(
                ErrorKind::Other,
                format!("找不到配置父项[{}]", parent),
            ));
        }
        let pr = pr.unwrap().as_table();
        if let None = pr {
            return Err(Error::new(
                ErrorKind::Other,
                format!("父项[{}]不是table", parent),
            ));
        }
        let pr = pr.unwrap();
        let cld = pr.get(child);
        if let None = cld {
            return Err(Error::new(
                ErrorKind::Other,
                format!("找不到配置子项[{}]", child),
            ));
        }
        let ret = cld.unwrap().as_str();
        if ret.is_none() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("配置子项[{}]转换字符串失败", child),
            ));
        }

        Ok(ret.unwrap().to_string())
    }
}
