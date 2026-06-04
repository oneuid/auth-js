import { AuthConfig } from './types';
import { OneUID } from './client';

export class DevicesClient {
  constructor(private config: AuthConfig, private root: OneUID) {}

  /**
   * Registers a new sovereign device as an HSM.
   * Sends the device name, unique ID, and generated public key to UID.ONE.
   */
  async register(params: {
    deviceId: string;
    deviceName: string;
    publicKey: string;
  }): Promise<{ status: string; message: string }> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to register a device");

    const response = await fetch(`${this.config.baseURL}/v1/auth/devices/register/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        device_id: params.deviceId,
        device_name: params.deviceName,
        public_key: params.publicKey
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || errorData.error || `Device registration failed: ${response.statusText}`);
    }

    return response.json();
  }

  /**
   * Verifies a target device in the Circle of Trust.
   * Signed by an already verified device's private key.
   */
  async verify(params: {
    targetDeviceId: string;
    verifyingDeviceId: string;
    signature: string;
  }): Promise<{ status: string; message: string }> {
    const token = await this.root.getAccessToken();
    if (!token) throw new Error("Must be authenticated to verify a device");

    const response = await fetch(`${this.config.baseURL}/v1/auth/devices/verify/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        target_device_id: params.targetDeviceId,
        verifying_device_id: params.verifyingDeviceId,
        signature: params.signature
      })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || errorData.error || `Device verification failed: ${response.statusText}`);
    }

    return response.json();
  }
}
