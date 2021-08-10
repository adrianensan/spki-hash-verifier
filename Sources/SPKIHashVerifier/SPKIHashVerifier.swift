import Foundation
import Security
import CommonCrypto

func copyKeyFrom(_ trust: SecTrust) -> SecKey? {
  if #available(iOS 14.0, iOSApplicationExtension 14.0,
                watchOS 7.0, watchOSApplicationExtension 7.0,
                tvOS 14.0, tvOSApplicationExtension 14.0,
                macOS 11.0, macOSApplicationExtension 11.0, *) {
    return SecTrustCopyKey(trust)
  } else {
    return SecTrustCopyPublicKey(trust)
  }
}

public class SPKIHashVerifier {
  
  struct PinnedHost {
    var host: String
    var spkiHashes: [String]
  }
  
  private let pinnedHashes: [String: [String]]
  private let whitelistedHosts: [String]
  private var allowUnkownHosts: Bool = false
  
  public init (pinnedHosts: [PinnedHost], whitelistedHosts: [String] = [], allowUnkownHosts: Bool = false) {
    var pinnedHashes: [String: [String]] = [:]
    pinnedHosts.forEach { pinnedHashes[$0.host] = $0.spkiHashes }
    self.pinnedHashes = pinnedHashes
    
    self.whitelistedHosts = whitelistedHosts
    self.allowUnkownHosts = allowUnkownHosts
  }
  
  public func verify(challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
      completionHandler(.performDefaultHandling, nil)
      return
    }
    
    let host = challenge.protectionSpace.host
    
    // Perform default authentication if host is whitelisted
    guard !whitelistedHosts.contains(host) else {
      completionHandler(.performDefaultHandling, nil)
      return
    }
    
    // Ensure domain is pinned
    guard let expectedSpkiHashes = pinnedHashes[host] else {
      if allowUnkownHosts { completionHandler(.performDefaultHandling, nil) }
      else { completionHandler(.cancelAuthenticationChallenge, nil) }
      return
    }
    
    // Get the public key and its Asn1Header information
    guard
      let trust = challenge.protectionSpace.serverTrust,
      let publicKey = copyKeyFrom(trust),
      let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, nil),
      let publicKeyAttributes: NSDictionary = SecKeyCopyAttributes(publicKey),
      let asn1HeaderType = Asn1Header.inferFrom(publicKeyType: publicKeyAttributes[kSecAttrKeyType] as? NSString,
                                                publicKeySize: publicKeyAttributes[kSecAttrKeySizeInBits] as? UInt32)
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    
    // Combine the appropriate Asn1Header data with the public key to form the SKPI
    let spkiBytes = asn1HeaderType.bytes + publicKeyData.bytes
    
    // Get the SHA256 hash of the SKPI
    var spkiHashBytes = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    CC_SHA256(spkiBytes, CC_LONG(spkiBytes.count), &spkiHashBytes)
    
    // Confirm the hash matches one of our pinned hashes
    if expectedSpkiHashes.contains(Data(spkiHashBytes).base64EncodedString()) {
      completionHandler(.performDefaultHandling, nil)
    }
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }
}
