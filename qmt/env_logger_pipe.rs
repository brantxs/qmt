use chrono::Local;
use chrono::NaiveDateTime;
use chrono::TimeZone;
use chrono_tz::Asia::Shanghai;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Result, Write};
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

pub struct PIPE {
    file: File,
    path: PathBuf,
    c_time: String,
    size: u64,
    stdout: bool,
}

impl PIPE {
    pub fn new(stdout: bool) -> Result<PIPE> {
        fs::create_dir_all("log")?;
        let path = std::path::Path::new("log").join("qmt_yg.log");
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        // 获取创建时间
        let file_meta = fs::metadata(&path)?;
        let c_time = file_meta.modified()?;
        let t = c_time.duration_since(UNIX_EPOCH);
        if let Err(e) = t {
            return Err(std::io::Error::new(ErrorKind::Other, e.to_string()));
        }
        let dt = NaiveDateTime::from_timestamp_millis(t.unwrap().as_millis() as i64);
        if let None = dt {
            return Err(std::io::Error::new(
                ErrorKind::Other,
                "获取日志文件创建时间错误",
            ));
        }
        let sh_dt = Shanghai
            .from_utc_datetime(&dt.unwrap())
            .date_naive()
            .to_string();
        Ok(PIPE {
            file,
            path,
            c_time: sh_dt,
            size: file_meta.len(),
            stdout,
        })
    }

    fn write_to_file(&mut self, buf: &[u8]) -> Result<()> {
        let now = Local::now();
        let today = now.date_naive().to_string();

        if today != self.c_time && self.size > 0 {
            // 修改文件名
            let new_path = std::path::Path::new("log").join(format!("qmt_yg.log.{}", self.c_time));
            fs::rename(&self.path, &new_path)?;
            // 新文件
            let path = std::path::Path::new("log").join("qmt_yg.log");
            let new_file = OpenOptions::new().create(true).append(true).open(&path)?;
            self.path = path;
            self.file = new_file;
            self.c_time = today;
            self.size = 0;
        }

        let size = self.file.write(buf)?;
        self.size += size as u64;
        Ok(())
    }
}

impl Write for PIPE {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        //let len = self.buf.write(buf)?;
        let len = buf.len();
        let line = String::from_utf8(buf.to_vec()).unwrap_or("----".to_string());

        if self.stdout {
            println!("{}", line);
        }
        self.write_to_file(buf)?;
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        //println!("{:?}", self.buf);
        Ok(())
    }
}
