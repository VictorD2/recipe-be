import * as bcrypt from 'bcrypt';

export class BcriptService {
  /**
   * Creating a hash with a text
   * @param text
   * @returns
   */
  async encrypt(text: string) {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(text, salt);
  }

  /**
   * Comparing a text with a hash
   * @param text
   * @param hash
   * @returns
   */
  async compare(text: string, hash: string) {
    return await bcrypt.compare(text, hash);
  }
}
