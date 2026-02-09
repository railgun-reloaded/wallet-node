declare module 'brittle' {
  export interface Test {
    ok(value: any, message?: string): void
    absent(value: any, message?: string): void
    is(actual: any, expected: any, message?: string): void
    not(actual: any, expected: any, message?: string): void
    alike(actual: any, expected: any, message?: string): void
    exception(fn: () => void, message?: string): void
    execution(fn: () => void, message?: string): void
    pass(message?: string): void
    fail(message?: string): void
    plan(count: number): void
    timeout(ms: number): void
  }

  export function test (name: string, fn: (t: Test) => void | Promise<void>): void
  export default test
}
