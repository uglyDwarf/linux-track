#ifndef HASHING__H
#define HASHING__H

#include <QCryptographicHash>
#include <QFile>
#include <QtDebug>
#include <QStringList>
#include <vector>
#include <stdint.h>


class FastHash{
 public:
  FastHash():buffer(length, 0), index{0}{};
  void init(){for(int i = 0; i < length; ++i) buffer[i] = 0; index = 0;};
  uint16_t hash(char val){
    buffer[index] = val;
    index = (index + 1) % length;
    uint16_t tmp = 0;
    for(int i = 0; i < length; ++i){
      if(tmp & 0x8000){
        tmp ^= 3;
      }
      tmp <<= 2;
      tmp ^= buffer[(index + i) % length];
    }
    return tmp;
  };
  int getLength()const{return length;};
  static const int length = 32;
 private:
  std::vector<uint8_t> buffer;
  int index;
};

class BlockId
{
 public:
  BlockId(const QString &n, const qint64 sz, const uint16_t f, 
          const QByteArray &m, const QByteArray &s): 
            name(n), size(sz), fast(f), md5(m), sha1(s), found(false){};
  void isBlock(QFile &f, const QString &destPath, QStringList &msgs);
  bool foundAlready()const{return found;};
  void clearFoundFlag(){found = false;};
  const QString &getFname()const{return name;};
  void save(QTextStream &stream){stream<<name<<" "<<size<<" "<<fast<<" "<<md5<<" "<<sha1<<"\n";};
 private:
  QString name;
  qint64 size;
  uint16_t fast;
  QByteArray md5, sha1;
  bool found;
};


bool hashFile(const QString fname, qint64 &size, uint16_t &fastVal, QByteArray &md5, 
              QByteArray &sha1);


#endif
