#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <unordered_map>

#include <unistd.h>
#include <ctime>

#include "pin.H"
#include "instlib.H"
#include "xed-interface.h"

std::ofstream error_log;

std::string log_name_prefix;
std::string log_name_suffix;


/* =========================================================================== */
/* Instruction Parsing Utilities                                               */
/* =========================================================================== */

std::unordered_map<std::string,std::string> iclass_from_icode;

// Returns instruction's icode, which is a custom instruction identifier
std::string get_instruction_icode(xed_decoded_inst_t *xedd) {
    char s_bits[5];

    const xed_inst_t* xi = xed_decoded_inst_inst(xedd);
    const unsigned int noperands = xed_inst_noperands(xi);

    // Iclass is also logged in result file
    std::string iclass = std::string(
        xed_iclass_enum_t2str(xed_decoded_inst_get_iclass(xedd))
    );

    // Icode consists of: iform + {operand_i}{width_i}...
    std::string icode  = std::string(
        xed_iform_enum_t2str(xed_decoded_inst_get_iform_enum(xedd))
    );

    // Iterate over every operand
    for (unsigned int i = 0; i < noperands; ++i) {
        const xed_operand_t* op = xed_inst_operand(xi, i);
        const xed_operand_enum_t op_name = xed_operand_name(op);

        std::string ops = "";

        switch (op_name) {
            // Agen
            case XED_OPERAND_AGEN:
                break;

            // Memory
            case XED_OPERAND_MEM0:
            case XED_OPERAND_MEM1: {
                // we print memops in a different function
                ops += "M";
                break;
            }

            // Pointers and branch displacements
            case XED_OPERAND_PTR:   
            case XED_OPERAND_RELBR: {
                ops += "Rel";
                break;
            }

            // Immediates
            case XED_OPERAND_IMM0:
            case XED_OPERAND_IMM1: {
                ops += "I";
                break;
            }

            // Registers
            case XED_OPERAND_REG0:
            case XED_OPERAND_REG1:
            case XED_OPERAND_REG2:
            case XED_OPERAND_REG3:
            case XED_OPERAND_REG4:
            case XED_OPERAND_REG5:
            case XED_OPERAND_REG6:
            case XED_OPERAND_REG7:
            case XED_OPERAND_REG8:
            case XED_OPERAND_BASE0:
            case XED_OPERAND_BASE1: {
                ops += "R";
                break;
            }
            default:
                // The default option should never occur a error is logged
                if (!error_log.is_open()) {
                    std::string error_log_name = log_name_prefix + "_error.log";
                    error_log.open(error_log_name.c_str(), std::ios_base::app);
                }

                error_log << "Unknown operator: " << icode << '\n';
                error_log.close();
        }

        // Only explicit operators are added to icode
        auto vis = xed_operand_operand_visibility(op);
        if (vis == XED_OPVIS_EXPLICIT && ops.size() > 0) {
            sprintf(s_bits, "%d", xed_decoded_inst_operand_length_bits(xedd, i));
            icode += "+" + ops + std::string(s_bits);
        }
    }

    iclass_from_icode[icode] = iclass;

    return icode;
}


/* =========================================================================== */
/* Thread Local Storage Utilities                                              */
/* =========================================================================== */

// Custom hash for faster usage of unordered_map
struct custom_hash_t {
    static uint64_t splitmix64(uint64_t x) {
        x += 0x9e3779b97f4a7c15;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
        x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
        return x ^ (x >> 31);
    }

    size_t operator()(uint64_t x) const {
        static const uint64_t FIXED_RANDOM = std::time(nullptr);
        return splitmix64(x + FIXED_RANDOM);
    }
};

// Padding is used to avoid false sharing
// 64 byte line size: 64 - 56 (sizeof(unordered_map))
#define PADSIZE 8

struct thread_data_t {
    std::unordered_map<uint64_t, uint64_t, custom_hash_t> counter;
    UINT8 _pad[PADSIZE];
};

static TLS_KEY tls_key;

// Returns thread local storage (TLS)
inline thread_data_t* get_tls(THREADID thread_id) {
    thread_data_t *tdata = static_cast<thread_data_t*>(
        PIN_GetThreadData(tls_key, thread_id)
    );
    return tdata;
}


/* =========================================================================== */
/* Analysis routines                                                           */
/* =========================================================================== */

// Executes before every basic block (BBL) is executed dynamically
VOID record_bbl(uint64_t addr, THREADID thread_id) {
    thread_data_t *tdata = get_tls(thread_id);

    // Count BBL occurence and stores inside TLS's counter
    tdata->counter[addr] += 1;
}


/* =========================================================================== */
/* Instrumentation routines                                                    */
/* =========================================================================== */

std::unordered_map<
    uint64_t, std::unordered_map<std::string, uint64_t>, custom_hash_t
> result_by_bbl;

// Iterates over all BBLs
VOID Trace(TRACE trace, VOID *v) {
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        uint64_t bbl_address = BBL_Address(bbl);

        auto bbl_counter = &(result_by_bbl[(uint64_t) bbl_address]);
        bbl_counter->clear();

        // Register analysis routine
        BBL_InsertCall(bbl, IPOINT_ANYWHERE,
                       (AFUNPTR) record_bbl,
                       IARG_UINT64, bbl_address,
                       IARG_THREAD_ID,
                       IARG_END);

        // Count instructions per BBL and store that as a partial result
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            xed_decoded_inst_t *xedd = INS_XedDec(ins);
            std::string code = get_instruction_icode(xedd);

            (*bbl_counter)[code] += 1;
        }
    }
}


/* =========================================================================== */
/* Callback Routines                                                           */
/* =========================================================================== */

PIN_LOCK lock;
INT32 num_threads = 0;

// Creates a thread data holder every time a thread starts
VOID ThreadStart(THREADID thread_id, CONTEXT *ctxt, INT32 flags, VOID *v) {
    PIN_GetLock(&lock, thread_id + 1);
    num_threads++;
    PIN_ReleaseLock(&lock);

    thread_data_t* tdata = new thread_data_t;

    PIN_SetThreadData(tls_key, tdata, thread_id);
}

// Executes when image is loaded
VOID ImageLoad(IMG img, VOID *v) {

    // Grab name of executable from image name
    if (IMG_IsMainExecutable(img)) {

        // Log name prefix contains executable name
        std::string exec_name = IMG_Name(img);
        exec_name = exec_name.substr(exec_name.rfind('/') + 1);
        log_name_prefix = exec_name;

        std::cerr << "[PIN] Initializing analysis for " << exec_name <<
            std::endl;

        // Log name suffix contains timestamp
        std::ostringstream slog_name_suffix;
        std::time_t timestamp = std::time(nullptr);
        slog_name_suffix << "ts" << timestamp << "_icode_log" << ".csv";
        log_name_suffix = slog_name_suffix.str();
    }
}

// Executes when program is finished
VOID Finish(INT32 code, VOID *v) {
    std::map<std::string, uint64_t> total_counter;

    std::cerr << "[PIN] Joining results from all " <<
        num_threads << " threads." << std::endl;

    // Aggregate data from all threads into "total_counter"
    for (int i = 0; i < num_threads; ++i) {
        thread_data_t* tdata = get_tls(i);

        for (auto &j : tdata->counter) {
            auto bbl_counter_ptr = &(result_by_bbl[j.first]);

            for (auto &k : (*bbl_counter_ptr)) {
                total_counter[k.first] += (k.second * j.second);
            }
        }
    }

    // Insert process id into file name
    std::ostringstream slog_name;
    slog_name << log_name_prefix << "_p" << getpid() << "_" << log_name_suffix;
    std::string log_name = slog_name.str();

    std::cerr << "[PIN] Writing results to " << log_name << std::endl;

    // Write result to CSV file
    std::ofstream result_csv;
    result_csv.open(log_name.c_str(), std::ios_base::app);
    result_csv << "icode,iclass,count" << '\n';

    for (auto &i : total_counter) {
        result_csv <<
                i.first << "," <<
                iclass_from_icode[i.first] << "," <<
                i.second << '\n';
    }

    result_csv.close();
    std::cerr << "[PIN] Done." << std::endl;
}


/* =========================================================================== */
/* Main                                                                        */
/* =========================================================================== */

int main(int argc, char **argv) {
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) {
        return -1;
    }

    xed_tables_init();

    tls_key = PIN_CreateThreadDataKey(0);


    IMG_AddInstrumentFunction(ImageLoad, 0);

    PIN_AddThreadStartFunction(ThreadStart, 0);

    TRACE_AddInstrumentFunction(Trace, 0);

    PIN_AddFiniFunction(Finish, 0);


    PIN_StartProgram();

    return 0;
}
