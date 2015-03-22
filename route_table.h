#define IP_ADDR_STR_LEN 19
#define MAC_ADDR_STR_LEN 20
#define IF_STR_LEN 5

/*typedef struct IP_table{
	char *dest_addr;
	char *gateway_addr;
	char *iface;
	struct IP_table *next;
}IP_table;

extern IP_table *head_ip_table;

IP_table *get_IP_table_row(char *ip);
*/

void populate_IP_table();
