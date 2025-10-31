void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Init services
  await Hive.initFlutter();
  final identity = IdentityService();
  if (!identity.hasIdentity) await identity.generateIdentity();
  
  final ipfs = IpfsService();
  await ipfs.init();

  runApp(TrueLedgerApp(identity: identity, ipfs: ipfs));
}