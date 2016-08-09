#include "fs.h"
#include "draw.h"
#include "platform.h"
#include "decryptor/hashfile.h"
#include "decryptor/nand.h"
#include "decryptor/nandfat.h"


u32 CtrNandTransfer(u32 param) {
    PartitionInfo* p_ctrnand = GetPartitionInfo(P_CTRNAND);
    PartitionInfo* p_firm0 = GetPartitionInfo(P_FIRM0);
    PartitionInfo* p_firm1 = GetPartitionInfo(P_FIRM1);
    char filename[64];
    char secnfoname[64];
    char hashname[64];
    bool a9lh = ((*(u32*) 0x101401C0) == 0);
    u32 region = GetRegion();
    
    // developer screwup protection
    if (!(param & N_NANDWRITE))
        return 1;
    
    // check free space
    if (!DebugCheckFreeSpace(128 * 1024 * 1024)) {
        Debug("You need at least 128MB free for this operation");
        return 1;
    }
    
    // set initial secureinfo name
    snprintf(secnfoname, 64, "transfer_SecureInfo_A");
    
    // select CTRNAND image for transfer
    Debug("Select CTRNAND image for transfer");
    if (InputFileNameSelector(filename, p_ctrnand->name, "bin", p_ctrnand->magic, 8, p_ctrnand->size, false) != 0)
        return 1;
    
    // SHA / region check
    u8 sha256[0x21]; // this needs a 0x20 + 0x01 byte .SHA file
    snprintf(hashname, 64, "%s.sha", filename);
    if (FileGetData(hashname, sha256, 0x21, 0) != 0x21) {
        Debug(".SHA file not found or too small");
        return 1;
    }
    // region check
    if (region != sha256[0x20]) {
        if (!a9lh) {
            Debug("Region does not match");
            return 1;
        } else {
            u8 secureinfo[0x111];
            do {
                Debug("Region does not match, select SecureInfo_A file");
                if (InputFileNameSelector(secnfoname, "SecureInfo_A", NULL, NULL, 0, 0x111, false) != 0)
                    return 1;
                if (FileGetData(secnfoname, secureinfo, 0x111, 0) != 0x111)
                    return 1;
            } while (region != (u32) secureinfo[0x100]);
        }
    }
    
    Debug("");
    Debug("Step #1: .SHA verification of CTRNAND image...");
    Debug("Checking hash from .SHA file...");
    if (CheckHashFromFile(hashname, 0, 0, sha256) != 0) {
        Debug("Failed, image corrupt or modified!");
        return 1;
    }
    Debug("Verified okay!");
    
    Debug("");
    Debug("Step #2: Dumping transfer files...");
    if ((DumpFile(F_TICKET | PO_TRANSFER) != 0) ||
        (DumpFile(F_CONFIGSAVE | PO_TRANSFER) != 0) ||
        (DumpFile(F_LOCALFRIEND | PO_TRANSFER) != 0) ||
        (DumpFile(F_MOVABLE | PO_TRANSFER) != 0) ||
        (DumpFile(F_SECUREINFO | PO_TRANSFER) != 0))
        return 1;
        
    Debug("");
    Debug("Step #3: Injecting CTRNAND image...");
    if (EncryptFileToNand(filename, p_ctrnand->offset, p_ctrnand->size, p_ctrnand) != 0)
        return 1;
    
    Debug("");
    Debug("Step #4: Injecting transfer files...");
    if ((InjectFile(N_NANDWRITE | F_TICKET | PO_TRANSFER) != 0) ||
        (InjectFile(N_NANDWRITE | F_CONFIGSAVE | PO_TRANSFER) != 0) ||
        (InjectFile(N_NANDWRITE | F_LOCALFRIEND | PO_TRANSFER) != 0) ||
        (InjectFile(N_NANDWRITE | F_MOVABLE | PO_TRANSFER) != 0))
        return 1;
    u32 offset;
    u32 size;
    if (DebugSeekFileInNand(&offset, &size, "SecureInfo_A", "RW         SYS        SECURE~?   ", p_ctrnand) != 0)
        return 1;
    if (EncryptFileToNand(secnfoname, offset, size, p_ctrnand) != 0)
        return 1;
    
    Debug("");
    Debug("Step #5: Fixing CMACs and paths...");
    if (AutoFixCtrnand(N_NANDWRITE) != 0)
        return 1;
    
    return 0;
}