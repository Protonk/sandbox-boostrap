'use strict';

send({
  kind: 'inspect-module',
  typeof_Module: typeof Module,
  module_keys: Object.keys(Module).sort(),
  typeof_findExportByName: typeof Module.findExportByName,
  typeof_getExportByName: typeof Module.getExportByName,
  typeof_findBaseAddress: typeof Module.findBaseAddress,
  typeof_enumerateExports: typeof Module.enumerateExports,
});
