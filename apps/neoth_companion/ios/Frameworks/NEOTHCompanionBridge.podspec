Pod::Spec.new do |spec|
  spec.name = 'NEOTHCompanionBridge'
  spec.version = '0.1.0'
  spec.summary = 'Reviewed native NEOTH companion bridge.'
  spec.platform = :ios, '13.0'
  spec.vendored_frameworks = 'NEOTHCompanionBridge.xcframework'
  # dart:ffi resolves these static Rust exports with DynamicLibrary.process().
  # Root each required C symbol so normal CocoaPods XCFramework selection pulls
  # its defining archive member even though Swift makes no direct bridge call.
  spec.user_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) -Wl,-u,_neoth_companion_bridge_new -Wl,-u,_neoth_companion_bridge_free -Wl,-u,_neoth_companion_pair_start -Wl,-u,_neoth_companion_reconnect_start -Wl,-u,_neoth_companion_chat_start -Wl,-u,_neoth_companion_operation_poll -Wl,-u,_neoth_companion_operation_cancel -Wl,-u,_neoth_companion_operation_free'
  }
end
