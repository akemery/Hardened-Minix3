#ifndef PEBS_H
#define PEBS_H

#define N_PEBS_RECORDS        1
#define DS_AREA_SIZE          1
#define USE_PEBS            1



struct pebs{
  u32_t eflags;// 0x00
  u32_t eip;	// 0x04
  u32_t eax;	// 0x08
  u32_t ebx;	// 0x0C
  u32_t ecx;	// 0x10
  u32_t edx;	// 0x14
  u32_t esi;	// 0x18
  u32_t edi;	// 0x1C
  u32_t ebp;	// 0x20
  u32_t esp;	// 0x24
};

struct ds_area{
  u32_t bts_buffer_base;		// 0x00 
  u32_t bts_index;			// 0x04
  u32_t bts_absolute_maximum;		// 0x08
  u32_t bts_interrupt_threshold;	// 0x0C
  struct pebs *pebs_buffer_base;	// 0x10
  struct pebs *pebs_index;		// 0x14
  struct pebs *pebs_absolute_maximum;	// 0x18
  struct pebs *pebs_interrupt_threshold;// 0x1C
  u32_t pebs_counter0_reset;		// 0x20
  u32_t pebs_counter1_reset;		// 0x24
  u32_t reserved;			// 0x30
};

struct pebs ppebs[N_PEBS_RECORDS + 1];
struct ds_area pds_area[DS_AREA_SIZE];
#endif /* PEBS_H */
