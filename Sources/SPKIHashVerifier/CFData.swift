import Foundation

extension CFData {
  var count: Int { CFDataGetLength(self) }
  
  var bytes: [UInt8] {
    var tempBytes = [UInt8](repeating: 0, count: count)
    CFDataGetBytes(self, CFRangeMake(0, count), &tempBytes)
    return tempBytes
  }
  
  var data: Data { Data(bytes) }
}
