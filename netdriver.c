

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netconf.h>
#include <linux/netdevice.h>
#include <linux/net_namespace.h>

//enp0s3

MODULE_AUTHOR("Carolina e Jonathan");
MODULE_DESCRIPTION("net driver module to collect statistics");
MODULE_INFO(difficulty, "very easy");
MODULE_LICENSE("GPL");

static __init int netdriver_init(void){
	pr_info("INICIO!\n");
		
	struct net_device *dev;
	read_lock(&dev_base_lock);
	dev = first_net_device(&init_net);
	while(dev){
		pr_info("interface [%s]:\n", dev->name);
		pr_info("\t\trx = %lu, tx = %lu\n", dev->stats.rx_packets, dev->stats.tx_packets); //struct net_device_stats *nds = simple_statfs(dev);
		
		dev = next_net_device(dev);
	}
	
	read_unlock(&dev_base_lock);
	
	return 0;
}

static __exit void netdriver_exit(void){
	pr_info("FIM!\n");
}

module_init(netdriver_init);
module_exit(netdriver_exit);

/*
int main(){
	
	//struct net_device snull_devs[1] = {
	//	{init: snull_init}
	//};
	
	struct net_device* dev = dev_get_by_name("enp0s3");
	
	if(dev == NULL) pr_info("NULO");
	else pr_info("EXISTE");
	
	return 0;
}
*/
