
// TODO: user specified server_id OR randomly generate one that does not already exists


// byte 1 = OK packet
// byte 2-5] = all zero packets
// byte 6 = mysql version (4) https://dev.mysql.com/doc/internals/en/binlog-version.html
//

// 00000000  00 00 00 00 00 04 01 00  00 00 32 00 00 00 00 00  |..........2.....|
// 00000010  00 00 20 00 9e 02 00 00  00 00 00 00 70 61 79 6d  |.. .........paym|
// 00000020  65 6e 74 2d 61 70 70 73  2d 62 69 6e 2e 30 30 30  |ent-apps-bin.000|
// 00000030  30 30 33 00 1c 88 43 5d  0f 01 00 00 00 77 00 00  |003...C].....w..|
// 00000040  00 00 00 00 00 00 00 04  00 35 2e 37 2e 31 38 2d  |.........5.7.18-|
// 00000050  31 36 2d 6c 6f 67 00 00  00 00 00 00 00 00 00 00  |16-log..........|
// 00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
// 00000070  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 13  |................|
// 00000080  38 0d 00 08 00 12 00 04  04 04 04 12 00 00 5f 00  |8............._.|
// 00000090  04 1a 08 00 00 00 08 08  08 02 00 00 00 0a 0a 0a  |................|

use crate::constants::{ColumnType};
use crate::io::ReadMysqlExt;
use byteorder::{LittleEndian as LE, ReadBytesExt, WriteBytesExt};
use std::io::{self, Write};
use std::fs::OpenOptions;
use std::collections::BTreeMap;

use std::iter::Iterator;

pub struct Reader {
    tables: BTreeMap<u64, TableMapEventPacket>,
    format: Option<FormatDescriptionEventPacket>,
}

impl Reader {
    pub fn new() -> Self {
        Self {
            tables: BTreeMap::new(),
            format: None,
        }
    }

    pub fn next_row_event(&mut self, mut payload: &[u8]) -> io::Result<Option<RowEvent>> {
        match EventPacket::parse(&payload) {
            Ok(EventPacket::Format(packet)) => {
                self.format = Some(packet);
                Ok(None)
            },
            Ok(EventPacket::TableMap(packet)) => {
                let table_id = packet.table_id;
                self.tables.insert(table_id, packet);
                Ok(None)
            },
            Ok(EventPacket::Rotate(packet)) => {
                Ok(None)
            },
            Ok(EventPacket::Insert(packet)) => {
                let row = self.make_row_event(packet)?;
                Ok(Some(RowEvent::Insert(row)))
            },
            Ok(EventPacket::Update(packet)) => {
                let row = self.make_row_event(packet)?;
                Ok(Some(RowEvent::Update(row)))
            },
            Ok(EventPacket::Delete(packet)) => {
                let row = self.make_row_event(packet)?;
                Ok(Some(RowEvent::Delete(row)))
            },
            Ok(EventPacket::Unhandled(event_type, _)) => {
                println!("unhandled event type 0x{:02x?}", event_type);
                Ok(None)
            }
            Err(err) => {
                panic!(err)
            }
        }
    }

    fn make_row_event(&mut self, packet: RowEventPacket) -> io::Result<Row> {
        Ok(Row)
    }
}

#[derive(Debug)]
pub enum RowEvent {
    Insert(Row),
    Update(Row),
    Delete(Row),
}

#[derive(Debug)]
pub struct Row;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[repr(u8)]
enum EventType {
    UNKNOWN_EVENT,
    START_EVENT_V3,
    QUERY_EVENT,
    STOP_EVENT,
    ROTATE_EVENT,
    INTVAR_EVENT,
    LOAD_EVENT,
    SLAVE_EVENT,
    CREATE_FILE_EVENT,
    APPEND_BLOCK_EVENT,
    EXEC_LOAD_EVENT,
    DELETE_FILE_EVENT,
    NEW_LOAD_EVENT,
    RAND_EVENT,
    USER_VAR_EVENT,
    FORMAT_DESCRIPTION_EVENT,
    XID_EVENT,
    BEGIN_LOAD_QUERY_EVENT,
    EXECUTE_LOAD_QUERY_EVENT,
    TABLE_MAP_EVENT,
    WRITE_ROWS_EVENTv0,
    UPDATE_ROWS_EVENTv0,
    DELETE_ROWS_EVENTv0,
    WRITE_ROWS_EVENTv1,
    UPDATE_ROWS_EVENTv1,
    DELETE_ROWS_EVENTv1,
    INCIDENT_EVENT,
    HEARTBEAT_EVENT,
    IGNORABLE_EVENT,
    ROWS_QUERY_EVENT,
    WRITE_ROWS_EVENTv2,
    UPDATE_ROWS_EVENTv2,
    DELETE_ROWS_EVENTv2,
    GTID_EVENT,
    ANONYMOUS_GTID_EVENT,
    PREVIOUS_GTIDS_EVENT,
}

impl From<u8> for EventType {
    fn from(x: u8) -> EventType {
        match x {
            0x00_u8 => EventType::UNKNOWN_EVENT,
            0x01_u8 => EventType::START_EVENT_V3,
            0x02_u8 => EventType::QUERY_EVENT,
            0x03_u8 => EventType::STOP_EVENT,
            0x04_u8 => EventType::ROTATE_EVENT,
            0x05_u8 => EventType::INTVAR_EVENT,
            0x06_u8 => EventType::LOAD_EVENT,
            0x07_u8 => EventType::SLAVE_EVENT,
            0x08_u8 => EventType::CREATE_FILE_EVENT,
            0x09_u8 => EventType::APPEND_BLOCK_EVENT,
            0x0a_u8 => EventType::EXEC_LOAD_EVENT,
            0x0b_u8 => EventType::DELETE_FILE_EVENT,
            0x0c_u8 => EventType::NEW_LOAD_EVENT,
            0x0d_u8 => EventType::RAND_EVENT,
            0x0e_u8 => EventType::USER_VAR_EVENT,
            0x0f_u8 => EventType::FORMAT_DESCRIPTION_EVENT,
            0x10_u8 => EventType::XID_EVENT,
            0x11_u8 => EventType::BEGIN_LOAD_QUERY_EVENT,
            0x12_u8 => EventType::EXECUTE_LOAD_QUERY_EVENT,
            0x13_u8 => EventType::TABLE_MAP_EVENT,
            0x14_u8 => EventType::WRITE_ROWS_EVENTv0,
            0x15_u8 => EventType::UPDATE_ROWS_EVENTv0,
            0x16_u8 => EventType::DELETE_ROWS_EVENTv0,
            0x17_u8 => EventType::WRITE_ROWS_EVENTv1,
            0x18_u8 => EventType::UPDATE_ROWS_EVENTv1,
            0x19_u8 => EventType::DELETE_ROWS_EVENTv1,
            0x1a_u8 => EventType::INCIDENT_EVENT,
            0x1b_u8 => EventType::HEARTBEAT_EVENT,
            0x1c_u8 => EventType::IGNORABLE_EVENT,
            0x1d_u8 => EventType::ROWS_QUERY_EVENT,
            0x1e_u8 => EventType::WRITE_ROWS_EVENTv2,
            0x1f_u8 => EventType::UPDATE_ROWS_EVENTv2,
            0x20_u8 => EventType::DELETE_ROWS_EVENTv2,
            0x21_u8 => EventType::GTID_EVENT,
            0x22_u8 => EventType::ANONYMOUS_GTID_EVENT,
            0x23_u8 => EventType::PREVIOUS_GTIDS_EVENT,
            _ => panic!("unknown event type")
        }
    }
}

// pub fn parse_event2(mut payload: &[u8]) -> io::Result<()> {
//     // skip OK byte
//     payload = &payload[1..];

//     // parse rotate event
//     let rotate_event = &payload[..45];
//     println!("{:02x?}", rotate_event);
//     payload = &payload[45..];
//     EventPacket::parse(rotate_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let format_event = &payload[..119];
//     println!("{:02x?}", format_event);
//     payload = &payload[119..];
//     EventPacket::parse(format_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let anonymous_gtid_event = &payload[..61];
//     println!("{:02x?}", anonymous_gtid_event);
//     payload = &payload[61..];
//     EventPacket::parse(anonymous_gtid_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let query_event = &payload[..68];
//     println!("{:02x?}", query_event);
//     payload = &payload[68..];
//     EventPacket::parse(query_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let table_map_event = &payload[..50];
//     println!("{:02x?}", table_map_event);
//     payload = &payload[50..];
//     EventPacket::parse(table_map_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let row_event = &payload[..55];
//     println!("{:02x?}", row_event);
//     payload = &payload[55..];
//     EventPacket::parse(row_event);

//     // skip OK byte
//     payload = &payload[1..];

//     let xid_event = &payload[..27];
//     println!("{:02x?}", xid_event);
//     payload = &payload[27..];
//     EventPacket::parse(xid_event);

//     Ok(())
// }

#[derive(Debug)]
enum EventPacket {
    TableMap(TableMapEventPacket),
    Rotate(RotateEventPacket),
    Format(FormatDescriptionEventPacket),
    Insert(RowEventPacket),
    Update(RowEventPacket),
    Delete(RowEventPacket),
    Unhandled(u8, Vec<u8>),
}

impl EventPacket {
    fn parse(mut payload: &[u8]) -> io::Result<EventPacket> {
        // skip OK byte
        payload = &payload[1..];

        // always assume version > 1
        if payload.len() < 19 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected len(event header) >= 19, got={}", payload.len()),
            ));
        }

        // event header
        let timestamp = payload.read_u32::<LE>()?;
        let event_type = payload.read_u8()?;
        let server_id = payload.read_u32::<LE>()?;
        let event_size = payload.read_u32::<LE>()?;
        let log_pos = payload.read_u32::<LE>()?;
        let flags = payload.read_u16::<LE>()?;

        // println!("timestamp = {:?}", timestamp);
        // println!("server_id = {:?}", server_id);
        // println!("event_type = {:#X?}", event_type);
        // println!("event_size = {:?}", event_size);
        // println!("log_pos = {:?}", log_pos);
        // println!("flags = {:#X?}", flags);

        payload = &payload[..(event_size as usize - 19)];

        let event = match EventType::from(event_type) {
            EventType::TABLE_MAP_EVENT => EventPacket::TableMap(TableMapEventPacket::parse(payload)?),
            EventType::ROTATE_EVENT => EventPacket::Rotate(RotateEventPacket::parse(payload)?),
            EventType::FORMAT_DESCRIPTION_EVENT => EventPacket::Format(FormatDescriptionEventPacket::parse(payload)?),
            EventType::WRITE_ROWS_EVENTv0 => EventPacket::Insert(RowEventPacket::parse(payload, false, false)?),
            EventType::WRITE_ROWS_EVENTv1 => EventPacket::Insert(RowEventPacket::parse(payload, false, false)?),
            EventType::WRITE_ROWS_EVENTv2 => EventPacket::Insert(RowEventPacket::parse(payload, true, false)?),
            EventType::UPDATE_ROWS_EVENTv0 => EventPacket::Update(RowEventPacket::parse(payload, false, false)?),
            EventType::UPDATE_ROWS_EVENTv1 => EventPacket::Update(RowEventPacket::parse(payload, false, true)?),
            EventType::UPDATE_ROWS_EVENTv2 => EventPacket::Update(RowEventPacket::parse(payload, true, true)?),
            EventType::DELETE_ROWS_EVENTv0 => EventPacket::Delete(RowEventPacket::parse(payload, false, false)?),
            EventType::DELETE_ROWS_EVENTv1 => EventPacket::Delete(RowEventPacket::parse(payload, false, false)?),
            EventType::DELETE_ROWS_EVENTv2 => EventPacket::Delete(RowEventPacket::parse(payload, true, false)?),
            unhandled_event_type => EventPacket::Unhandled(unhandled_event_type as u8, payload.into()),
        };

        match event {
            EventPacket::Unhandled(unhandled_event_type, _) => {
                println!("unhandled event type = {:?}", EventType::from(unhandled_event_type))
            },
            ref event => println!("{:#?}", event),
        }

        Ok(event)
    }
}

#[derive(Debug)]
struct RotateEventPacket {
    position: u64,
    next_log_name: String,
}

impl RotateEventPacket {
    fn parse(mut payload: &[u8]) -> io::Result<RotateEventPacket> {
        let position = payload.read_u64::<LE>()?;
        let next_log_name = String::from_utf8(Vec::from(payload)).unwrap();

        Ok(RotateEventPacket{
            position: position,
            next_log_name: next_log_name,
        })
    }
}

#[derive(Debug)]
struct TableMapEventPacket {
    table_id: u64,
    flags: u16,
    schema: String,
    table: String,
    column_count: u64,
    column_types: Vec<ColumnType>,
    column_metas: Vec<u16>,
    null_bitmap: Vec<u8>,
}


impl TableMapEventPacket {
    fn parse(mut payload: &[u8]) -> io::Result<TableMapEventPacket> {
        let table_id = payload.read_uint::<LE>(6)?; // this is actually a fixed length (either 4 or 6 bytes)
        let flags = payload.read_u16::<LE>()?;

        let schema_len = payload.read_u8()? as usize;
        let schema = String::from_utf8(Vec::from(&payload[..schema_len])).unwrap();
        payload = &payload[schema_len..]; // move cursor
        // println!("schema = {:?}", schema);

        // skip 0x00
        payload = &payload[1..];

        let table_len = payload.read_u8()? as usize;
        let table = String::from_utf8(Vec::from(&payload[..table_len])).unwrap();
        payload = &payload[table_len..]; // move cursor
        // println!("table = {:?}", table);

        // skip 0x00
        payload = &payload[1..];

        let column_count = payload.read_lenenc_int()? as usize;
        let column_types : Vec<ColumnType> = payload[..column_count].iter()
            .cloned()
            .map(ColumnType::from)
            .collect();


        let mut column_metas = vec![0; column_count];

        let mut column_meta_reader = read_lenenc_str!(&mut payload)?;

        for (i, t) in column_types.iter().enumerate() {
            match t {
                // 2 bytes
                ColumnType::MYSQL_TYPE_STRING
                    | ColumnType::MYSQL_TYPE_NEWDECIMAL
                    | ColumnType::MYSQL_TYPE_VAR_STRING
                    | ColumnType::MYSQL_TYPE_VARCHAR
                    | ColumnType::MYSQL_TYPE_BIT => {
                        // TODO: there is a off by one somewhere, and this should be using read_u16;
                        // println!("a {:?}, {:?}", t, column_meta_reader);
                        column_metas[i] = column_meta_reader.read_u8().unwrap() as u16;
                    }

                // 1 byte
                ColumnType::MYSQL_TYPE_BLOB
                    | ColumnType::MYSQL_TYPE_DOUBLE
                    | ColumnType::MYSQL_TYPE_FLOAT
                    | ColumnType::MYSQL_TYPE_GEOMETRY
                    | ColumnType::MYSQL_TYPE_JSON => {
                        // println!("b {:?}", t);
                        column_metas[i] = column_meta_reader.read_u8().unwrap() as u16;
                    }

                // maybe 1 byte?
                ColumnType::MYSQL_TYPE_TIME2
                    | ColumnType::MYSQL_TYPE_DATETIME2
                    | ColumnType::MYSQL_TYPE_TIMESTAMP2 => {
                        // println!("c {:?}", t);
                        column_metas[i] = column_meta_reader.read_u8().unwrap() as u16;
                    }

                // 0 byte
                ColumnType::MYSQL_TYPE_DECIMAL
                    | ColumnType::MYSQL_TYPE_TINY
                    | ColumnType::MYSQL_TYPE_SHORT
                    | ColumnType::MYSQL_TYPE_LONG
                    | ColumnType::MYSQL_TYPE_NULL
                    | ColumnType::MYSQL_TYPE_TIMESTAMP
                    | ColumnType::MYSQL_TYPE_LONGLONG
                    | ColumnType::MYSQL_TYPE_INT24
                    | ColumnType::MYSQL_TYPE_DATE
                    | ColumnType::MYSQL_TYPE_TIME
                    | ColumnType::MYSQL_TYPE_DATETIME
                    | ColumnType::MYSQL_TYPE_YEAR => {
                        // println!("d {:?}", t);
                        column_metas[i] = 0_u16;
                    }

                _ => panic!("{:?} not supported", t)
            }
        }


        let null_bitmap = if payload.len() == (column_count+7) / 8 {
            Vec::from(payload)
        } else {
            Vec::new()
        };

        Ok(TableMapEventPacket {
            table_id: table_id,
            flags: flags,
            schema: schema,
            table: table,
            column_count: column_count as u64,
            column_types: column_types,
            column_metas: column_metas,
            null_bitmap: null_bitmap,
        })
    }
}

#[derive(Debug)]
struct FormatDescriptionEventPacket {
    version: u16,
    server_version: String,
    create_timestamp: u32,
    event_header_length: u8,
    event_type_header_lengths: Vec<u8>,
}

impl FormatDescriptionEventPacket {
    fn parse(mut payload: &[u8]) -> io::Result<FormatDescriptionEventPacket> {
        let version = payload.read_u16::<LE>()?;
        let server_version = String::from_utf8(Vec::from(&payload[..50]))
            .unwrap()
            .trim_matches(char::from(0))
            .to_string();

        payload = &payload[50..];

        let create_timestamp = payload.read_u32::<LE>()?;
        let event_header_length = payload.read_u8()?;

        let event_type_header_lengths = Vec::from(payload);

        Ok(FormatDescriptionEventPacket {
            version: version,
            server_version: server_version,
            create_timestamp: create_timestamp,
            event_header_length: event_header_length,
            event_type_header_lengths: event_type_header_lengths,
        })
    }
}

#[derive(Debug)]
struct RowEventPacket {
    table_id: u64,
    flags: u16,
    extras: Vec<u8>,
    column_count: u64,
    column_bitmap1: Vec<u8>,
    column_bitmap2: Vec<u8>,
    rows: Vec<u8>,
}

impl RowEventPacket {
    fn parse(mut payload: &[u8], use_extras: bool, use_bitmap2: bool) -> io::Result<RowEventPacket> {
        let table_id = payload.read_uint::<LE>(6)?;
        let flags = payload.read_u16::<LE>()?;

        let extras = if use_extras {
            let extras_len = payload.read_u16::<LE>()? as usize - 2;
            let extras_data = &payload[..extras_len];
            payload = &payload[extras_len..];

            Vec::from(extras_data)
        } else {
            Vec::new()
        };

        let column_count = payload.read_lenenc_int()?;

        let bitmap_size = ((column_count + 7) / 8) as usize;

        let column_bitmap1 = Vec::from(&payload[..bitmap_size]);
        payload = &payload[bitmap_size..];

        let column_bitmap2 = if use_bitmap2 {
            let column_bitmap2_data = &payload[..bitmap_size];
            payload = &payload[bitmap_size..];
            Vec::from(column_bitmap2_data)
        } else {
            Vec::new()
        };

        let rows = Vec::from(payload);

        Ok(RowEventPacket {
            table_id: table_id,
            flags: flags,
            extras: extras,
            column_count: column_count,
            column_bitmap1: column_bitmap1,
            column_bitmap2: column_bitmap2,
            rows: rows,
        })
    }
}

#[cfg(test)]
mod test {
    use super::{Reader};
    use std::iter::Iterator;

    #[test]
    fn parses_row_event() {
        // 00000000  00 00 00 00 00 04 01 00  00 00 2d 00 00 00 00 00  |..........-.....|
        // 00000010  00 00 20 00 96 00 00 00  00 00 00 00 73 68 6f 70  |.. .........shop|
        // 00000020  69 66 79 2d 62 69 6e 2e  30 30 30 30 30 35 00 f2  |ify-bin.000005..|
        // 00000030  43 5d 5d 0f 01 00 00 00  77 00 00 00 00 00 00 00  |C]].....w.......|
        // 00000040  00 00 04 00 35 2e 37 2e  31 38 2d 31 36 2d 6c 6f  |....5.7.18-16-lo|
        // 00000050  67 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |g...............|
        // 00000060  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        // 00000070  00 00 00 00 00 00 00 00  00 00 13 38 0d 00 08 00  |...........8....|
        // 00000080  12 00 04 04 04 04 12 00  00 5f 00 04 1a 08 00 00  |........._......|
        // 00000090  00 08 08 08 02 00 00 00  0a 0a 0a 2a 2a 00 12 34  |...........**..4|
        // 000000a0  00 00 c2 36 0c df 00 fc  5a 5d 5d 22 01 00 00 00  |...6....Z]]"....|
        // 000000b0  3d 00 00 00 d3 00 00 00  00 00 01 00 00 00 00 00  |=...............|
        // 000000c0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
        // 000000d0  00 00 00 02 00 00 00 00  00 00 00 00 01 00 00 00  |................|
        // 000000e0  00 00 00 00 00 fc 5a 5d  5d 02 01 00 00 00 44 00  |......Z]].....D.|
        // 000000f0  00 00 17 01 00 00 08 00  3b 18 00 00 00 00 00 00  |........;.......|
        // 00000100  04 00 00 1a 00 00 00 00  00 00 01 00 00 00 40 00  |..............@.|
        // 00000110  00 00 00 06 03 73 74 64  04 21 00 21 00 2d 00 70  |.....std.!.!.-.p|
        // 00000120  65 74 73 00 42 45 47 49  4e 00 fc 5a 5d 5d 13 01  |ets.BEGIN..Z]]..|
        // 00000130  00 00 00 32 00 00 00 49  01 00 00 00 00 2d 0a 00  |...2...I.....-..|
        // 00000140  00 00 00 01 00 04 70 65  74 73 00 04 63 61 74 73  |......pets..cats|
        // 00000150  00 04 03 0f 0f 0a 04 58  02 58 02 00 00 fc 5a 5d  |.......X.X....Z]|
        // 00000160  5d 1e 01 00 00 00 37 00  00 00 80 01 00 00 00 00  |].....7.........|
        // 00000170  2d 0a 00 00 00 00 01 00  02 00 04 ff f0 04 00 00  |-...............|
        // 00000180  00 07 00 43 68 61 72 6c  69 65 05 00 52 69 76 65  |...Charlie..Rive|
        // 00000190  72 b5 c0 0f 00 fc 5a 5d  5d 10 01 00 00 00 1b 00  |r.....Z]].......|
        // 000001a0  00 00 9b 01 00 00 00 00  72 0e 00 00 00 00 00 00  |........r.......|

        // const A : &[u8] = b"\x00\x00\x00\x00\x00\x04\x01\x00\x00\x00\x2d\x00\x00\x00\x00\x00\
        //                     \x00\x00\x20\x00\x96\x00\x00\x00\x00\x00\x00\x00\x73\x68\x6f\x70\
        //                     \x69\x66\x79\x2d\x62\x69\x6e\x2e\x30\x30\x30\x30\x30\x35";

        // const B : &[u8] = b"\x00\xf2\
        //     \x43\x5d\x5d\x0f\x01\x00\x00\x00\x77\x00\x00\x00\x00\x00\x00\x00\
        //     \x00\x00\x04\x00\x35\x2e\x37\x2e\x31\x38\x2d\x31\x36\x2d\x6c\x6f\
        //     \x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //     \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x38\x0d\x00\x08\x00\
        //     \x12\x00\x04\x04\x04\x04\x12\x00\x00\x5f\x00\x04\x1a\x08\x00\x00\
        //     \x00\x08\x08\x08\x02\x00\x00\x00\x0a\x0a\x0a\x2a\x2a\x00\x12\x34\
        //     \x00\x00\xc2\x36\x0c\xdf";

        const ROTATE_EVENT : &[u8] = b"\x00\x00\x00\x00\x00\x04\x01\x00\x00\x00\x2d\x00\x00\x00\x00\x00\x00\x00\x20\x00\x96\x00\x00\x00\x00\x00\x00\x00\x73\x68\x6f\x70\x69\x66\x79\x2d\x62\x69\x6e\x2e\x30\x30\x30\x30\x30\x35";
        const FORMAT_DESCRIPTION_EVENT : &[u8] = b"\x00\xf2\x43\x5d\x5d\x0f\x01\x00\x00\x00\x77\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x35\x2e\x37\x2e\x31\x38\x2d\x31\x36\x2d\x6c\x6f\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x38\x0d\x00\x08\x00\x12\x00\x04\x04\x04\x04\x12\x00\x00\x5f\x00\x04\x1a\x08\x00\x00\x00\x08\x08\x08\x02\x00\x00\x00\x0a\x0a\x0a\x2a\x2a\x00\x12\x34\x00\x00\xc2\x36\x0c\xdf";
        const ANONYMOUS_GTID_EVENT : &[u8] = b"\x00\xfc\x5a\x5d\x5d\x22\x01\x00\x00\x00\x3d\x00\x00\x00\xd3\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00";
        const QUERY_EVENT : &[u8] = b"\x00\xfc\x5a\x5d\x5d\x02\x01\x00\x00\x00\x44\x00\x00\x00\x17\x01\x00\x00\x08\x00\x3b\x18\x00\x00\x00\x00\x00\x00\x04\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x40\x00\x00\x00\x00\x06\x03\x73\x74\x64\x04\x21\x00\x21\x00\x2d\x00\x70\x65\x74\x73\x00\x42\x45\x47\x49\x4e";
        const TABLE_MAP_EVENT : &[u8] = b"\x00\xfc\x5a\x5d\x5d\x13\x01\x00\x00\x00\x32\x00\x00\x00\x49\x01\x00\x00\x00\x00\x2d\x0a\x00\x00\x00\x00\x01\x00\x04\x70\x65\x74\x73\x00\x04\x63\x61\x74\x73\x00\x04\x03\x0f\x0f\x0a\x04\x58\x02\x58\x02\x00";
        const INSERT_ROW_EVENT : &[u8] = b"\x00\xfc\x5a\x5d\x5d\x1e\x01\x00\x00\x00\x37\x00\x00\x00\x80\x01\x00\x00\x00\x00\x2d\x0a\x00\x00\x00\x00\x01\x00\x02\x00\x04\xff\xf0\x04\x00\x00\x00\x07\x00\x43\x68\x61\x72\x6c\x69\x65\x05\x00\x52\x69\x76\x65\x72\xb5\xc0\x0f";
        const XID_EVENT : &[u8] = b"\x00\xfc\x5a\x5d\x5d\x10\x01\x00\x00\x00\x1b\x00\x00\x00\x9b\x01\x00\x00\x00\x00\x72\x0e\x00\x00\x00\x00\x00\x00";

        let events = vec![
            ROTATE_EVENT.to_vec(),
            FORMAT_DESCRIPTION_EVENT.to_vec(),
            ANONYMOUS_GTID_EVENT.to_vec(),
            QUERY_EVENT.to_vec(),
            TABLE_MAP_EVENT.to_vec(),
            INSERT_ROW_EVENT.to_vec(),
            XID_EVENT.to_vec(),
        ];

        let mut reader = Reader::new();
        for e in events {
            reader.next_row_event(&e);
        }
        // for lol in Reader::new(events.iter()) {
        //     println!("{:?}", lol);
        // }
        // let mut reader = ;
        // reader.next();
        // reader.next();
        // reader.next();
        // reader.next();
        // reader.next();
        // reader.next();
        // reader.next();

        // const EVENT : &[u8] = b"\x00\x00\x00\x00\x00\x04\x01\x00\x00\x00\x2d\x00\x00\x00\x00\x00\
        //                         \x00\x00\x20\x00\x96\x00\x00\x00\x00\x00\x00\x00\x73\x68\x6f\x70\
        //                         \x69\x66\x79\x2d\x62\x69\x6e\x2e\x30\x30\x30\x30\x30\x35\x00\xf2\
        //                         \x43\x5d\x5d\x0f\x01\x00\x00\x00\x77\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x04\x00\x35\x2e\x37\x2e\x31\x38\x2d\x31\x36\x2d\x6c\x6f\
        //                         \x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x38\x0d\x00\x08\x00\
        //                         \x12\x00\x04\x04\x04\x04\x12\x00\x00\x5f\x00\x04\x1a\x08\x00\x00\
        //                         \x00\x08\x08\x08\x02\x00\x00\x00\x0a\x0a\x0a\x2a\x2a\x00\x12\x34\
        //                         \x00\x00\xc2\x36\x0c\xdf\x00\xfc\x5a\x5d\x5d\x22\x01\x00\x00\x00\
        //                         \x3d\x00\x00\x00\xd3\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\xfc\x5a\x5d\x5d\x02\x01\x00\x00\x00\x44\x00\
        //                         \x00\x00\x17\x01\x00\x00\x08\x00\x3b\x18\x00\x00\x00\x00\x00\x00\
        //                         \x04\x00\x00\x1a\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x40\x00\
        //                         \x00\x00\x00\x06\x03\x73\x74\x64\x04\x21\x00\x21\x00\x2d\x00\x70\
        //                         \x65\x74\x73\x00\x42\x45\x47\x49\x4e\x00\xfc\x5a\x5d\x5d\x13\x01\
        //                         \x00\x00\x00\x32\x00\x00\x00\x49\x01\x00\x00\x00\x00\x2d\x0a\x00\
        //                         \x00\x00\x00\x01\x00\x04\x70\x65\x74\x73\x00\x04\x63\x61\x74\x73\
        //                         \x00\x04\x03\x0f\x0f\x0a\x04\x58\x02\x58\x02\x00\x00\xfc\x5a\x5d\
        //                         \x5d\x1e\x01\x00\x00\x00\x37\x00\x00\x00\x80\x01\x00\x00\x00\x00\
        //                         \x2d\x0a\x00\x00\x00\x00\x01\x00\x02\x00\x04\xff\xf0\x04\x00\x00\
        //                         \x00\x07\x00\x43\x68\x61\x72\x6c\x69\x65\x05\x00\x52\x69\x76\x65\
        //                         \x72\xb5\xc0\x0f\x00\xfc\x5a\x5d\x5d\x10\x01\x00\x00\x00\x1b\x00\
        //                         \x00\x00\x9b\x01\x00\x00\x00\x00\x72\x0e\x00\x00\x00\x00\x00\x00";




        // const EVENT2 : &[u8] = b"\x00\xf2\x43\x5d\x5d\x0f\x01\x00\x00\x00\x77\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x04\x00\x35\x2e\x37\x2e\x31\x38\x2d\x31\x36\x2d\
        //                         \x6c\x6f\x67\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
        //                         \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x13\x38\x0d\x00\
        //                         \x08\x00\x12\x00\x04\x04\x04\x04\x12\x00\x00\x5f\x00\x04\x1a\x08\
        //                         \x00\x00\x00\x08\x08\x08\x02\x00\x00\x00\x0a\x0a\x0a\x2a\x2a\x00";

        // parse_event2(EVENT).unwrap();
    }
}
